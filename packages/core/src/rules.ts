// packages/core/src/rules.ts
//
// Minimal JSONLogic evaluator, vendored into core (JSONLogic is data, not
// code — there is no eval here, no sandbox to escape, and no way for a
// rule to touch anything but the data object it is given).
//
// Supported operations: var, ==, !=, ===, !==, >, >=, <, <=, !, !!,
// and, or, if, in, missing, filter, map, all, some, none, +, -, *, /, %.
// Any unknown operation throws — a rule that cannot be evaluated aborts
// adjudication (the engine throws RuleError; the server rolls the whole
// adjudication back and returns 400) instead of silently evaluating to false.
//
// Semantics follow the JSONLogic spec: `and`/`or` return values (first
// falsy / first truthy, else the last value); `if` takes
// cond/then pairs plus an optional else; `var` takes a dotted path with
// an optional default; `all` over an empty array is true, `some` over an
// empty array is false. Arithmetic throws on non-finite results so money
// and counts can never silently become NaN or Infinity.

export class RuleError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RuleError";
  }
}

export type JsonLogic = unknown;

function isObject(v: unknown): v is Record<string, unknown> {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function truthy(v: unknown): boolean {
  return !!v;
}

function resolveVar(path: unknown, data: unknown): unknown {
  if (typeof path !== "string") {
    throw new RuleError("var path must be a string");
  }
  if (path === "") return data;
  const parts = path.split(".");
  let cur: unknown = data;
  for (const part of parts) {
    if (cur === null || cur === undefined) return undefined;
    if (Array.isArray(cur)) {
      const idx = Number(part);
      if (!Number.isInteger(idx) || idx < 0) return undefined;
      cur = cur[idx];
    } else if (typeof cur === "object") {
      // Own properties only: rules must never read prototype members
      // (constructor, __proto__) off the data object.
      if (!Object.prototype.hasOwnProperty.call(cur, part)) return undefined;
      cur = (cur as Record<string, unknown>)[part];
    } else {
      return undefined;
    }
  }
  return cur;
}

function toNumber(v: unknown, op: string): number {
  const n = typeof v === "number" ? v : Number(v);
  if (typeof n !== "number" || !Number.isFinite(n)) {
    throw new RuleError(`${op}: operand is not a finite number`);
  }
  return n;
}

function looseEqual(a: unknown, b: unknown): boolean {
  // JSONLogic == is JavaScript loose equality.
  // eslint-disable-next-line eqeqeq
  return a == b;
}

export const MAX_RULE_DEPTH = 100;

export function evaluate(logic: JsonLogic, data: unknown, depth = 0): unknown {
  if (depth > MAX_RULE_DEPTH) {
    throw new RuleError(`rule exceeds maximum nesting depth (${MAX_RULE_DEPTH})`);
  }
  if (logic === null || typeof logic !== "object") return logic;
  if (Array.isArray(logic)) {
    return logic.map((v) => evaluate(v, data, depth + 1));
  }
  const keys = Object.keys(logic);
  if (keys.length !== 1) {
    throw new RuleError("a rule object must have exactly one operation");
  }
  const op = keys[0];
  const rawArgs = (logic as Record<string, unknown>)[op];
  const args = Array.isArray(rawArgs) ? rawArgs : [rawArgs];

  switch (op) {
    case "var": {
      const path = args[0];
      const value = resolveVar(path, data);
      if (value === undefined && args.length > 1) {
        return evaluate(args[1], data, depth + 1);
      }
      return value === undefined ? null : value;
    }
    case "==": {
      if (args.length !== 2) throw new RuleError("== takes exactly 2 arguments");
      return looseEqual(evaluate(args[0], data, depth + 1), evaluate(args[1], data, depth + 1));
    }
    case "!=": {
      if (args.length !== 2) throw new RuleError("!= takes exactly 2 arguments");
      return !looseEqual(evaluate(args[0], data, depth + 1), evaluate(args[1], data, depth + 1));
    }
    case "===": {
      if (args.length !== 2) throw new RuleError("=== takes exactly 2 arguments");
      return evaluate(args[0], data, depth + 1) === evaluate(args[1], data, depth + 1);
    }
    case "!==": {
      if (args.length !== 2) throw new RuleError("!== takes exactly 2 arguments");
      return evaluate(args[0], data, depth + 1) !== evaluate(args[1], data, depth + 1);
    }
    case ">":
    case ">=":
    case "<":
    case "<=": {
      if (args.length !== 2) throw new RuleError(`${op} takes exactly 2 arguments`);
      const a = toNumber(evaluate(args[0], data, depth + 1), op);
      const b = toNumber(evaluate(args[1], data, depth + 1), op);
      if (op === ">") return a > b;
      if (op === ">=") return a >= b;
      if (op === "<") return a < b;
      return a <= b;
    }
    case "!": {
      if (args.length !== 1) throw new RuleError("! takes exactly 1 argument");
      return !truthy(evaluate(args[0], data, depth + 1));
    }
    case "!!": {
      if (args.length !== 1) throw new RuleError("!! takes exactly 1 argument");
      return truthy(evaluate(args[0], data, depth + 1));
    }
    case "and": {
      let result: unknown = true;
      for (const a of args) {
        result = evaluate(a, data, depth + 1);
        if (!truthy(result)) return result;
      }
      return result;
    }
    case "or": {
      let result: unknown = false;
      for (const a of args) {
        result = evaluate(a, data, depth + 1);
        if (truthy(result)) return result;
      }
      return result;
    }
    case "if": {
      for (let i = 0; i + 1 < args.length; i += 2) {
        if (truthy(evaluate(args[i], data, depth + 1))) return evaluate(args[i + 1], data, depth + 1);
      }
      if (args.length % 2 === 1) return evaluate(args[args.length - 1], data, depth + 1);
      return null;
    }
    case "in": {
      if (args.length !== 2) throw new RuleError("in takes exactly 2 arguments");
      const needle = evaluate(args[0], data, depth + 1);
      const hay = evaluate(args[1], data, depth + 1);
      if (typeof hay === "string" && typeof needle === "string") {
        return hay.includes(needle);
      }
      if (Array.isArray(hay)) return hay.includes(needle);
      throw new RuleError("in: haystack must be a string or array");
    }
    case "missing": {
      const names = args.flatMap((a) => {
        const v = evaluate(a, data, depth + 1);
        return Array.isArray(v) ? v : [v];
      });
      const out: unknown[] = [];
      for (const name of names) {
        if (typeof name !== "string") throw new RuleError("missing: var names must be strings");
        if (resolveVar(name, data) === undefined) out.push(name);
      }
      return out;
    }
    case "filter": {
      if (args.length !== 2) throw new RuleError("filter takes exactly 2 arguments");
      const arr = evaluate(args[0], data, depth + 1);
      if (!Array.isArray(arr)) throw new RuleError("filter: first argument must be an array");
      return arr.filter((el) => truthy(evaluate(args[1], el, depth + 1)));
    }
    case "map": {
      if (args.length !== 2) throw new RuleError("map takes exactly 2 arguments");
      const arr = evaluate(args[0], data, depth + 1);
      if (!Array.isArray(arr)) throw new RuleError("map: first argument must be an array");
      return arr.map((el) => evaluate(args[1], el, depth + 1));
    }
    case "all":
    case "some":
    case "none": {
      if (args.length !== 2) throw new RuleError(`${op} takes exactly 2 arguments`);
      const arr = evaluate(args[0], data, depth + 1);
      if (!Array.isArray(arr)) throw new RuleError(`${op}: first argument must be an array`);
      if (op === "all") return arr.every((el) => truthy(evaluate(args[1], el, depth + 1)));
      if (op === "some") return arr.some((el) => truthy(evaluate(args[1], el, depth + 1)));
      return !arr.some((el) => truthy(evaluate(args[1], el, depth + 1)));
    }
    case "+": {
      if (args.length === 1) return toNumber(evaluate(args[0], data, depth + 1), "+");
      let sum = 0;
      for (const a of args) sum += toNumber(evaluate(a, data, depth + 1), "+");
      if (!Number.isFinite(sum)) throw new RuleError("+: non-finite result");
      return sum;
    }
    case "-": {
      if (args.length === 1) return -toNumber(evaluate(args[0], data, depth + 1), "-");
      if (args.length !== 2) throw new RuleError("- takes 1 or 2 arguments");
      const r = toNumber(evaluate(args[0], data, depth + 1), "-") - toNumber(evaluate(args[1], data, depth + 1), "-");
      if (!Number.isFinite(r)) throw new RuleError("-: non-finite result");
      return r;
    }
    case "*": {
      let prod = 1;
      for (const a of args) prod *= toNumber(evaluate(a, data, depth + 1), "*");
      if (!Number.isFinite(prod)) throw new RuleError("*: non-finite result");
      return prod;
    }
    case "/": {
      if (args.length !== 2) throw new RuleError("/ takes exactly 2 arguments");
      const a = toNumber(evaluate(args[0], data, depth + 1), "/");
      const b = toNumber(evaluate(args[1], data, depth + 1), "/");
      if (b === 0) throw new RuleError("/: division by zero");
      const r = a / b;
      if (!Number.isFinite(r)) throw new RuleError("/: non-finite result");
      return r;
    }
    case "%": {
      if (args.length !== 2) throw new RuleError("% takes exactly 2 arguments");
      const a = toNumber(evaluate(args[0], data, depth + 1), "%");
      const b = toNumber(evaluate(args[1], data, depth + 1), "%");
      if (b === 0) throw new RuleError("%: division by zero");
      return a % b;
    }
    default:
      throw new RuleError(`unknown operation: ${op}`);
  }
}
