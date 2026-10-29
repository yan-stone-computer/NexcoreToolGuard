import { createHash } from "node:crypto";

export type ToolRisk = "read" | "write" | "command" | "network";
export type ToolCall = {
  id: string;
  name: string;
  arguments: unknown;
};

export type ToolSpec = {
  name: string;
  source?: string;
  scope: "read" | "write";
  risk: ToolRisk;
  timeoutMs: number;
  idempotent?: boolean;
  sensitive?: boolean;
  approval?: "never" | "write" | "always";
};

export type ApprovalGrant = {
  tool: string;
  digest: string;
  expiresAt: number;
};

export type GuardDecision =
  | { effect: "allow"; spec: ToolSpec }
  | { effect: "approval"; spec: ToolSpec; digest: string; reason: string }
  | { effect: "deny"; reason: string; code: string };

export type GuardOptions = {
  maxCallsPerRun?: number;
  maxFailures?: number;
  approvalTtlMs?: number;
  now?: () => number;
};

function stable(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
  return "{" + Object.keys(value as Record<string, unknown>).sort().map(key => JSON.stringify(key) + ":" + stable((value as Record<string, unknown>)[key])).join(",") + "}";
}

/** Digest the exact tool name and canonicalized arguments, not just the tool name. */
export function callDigest(call: ToolCall): string {
  return createHash("sha256").update(`${call.name}\0${stable(call.arguments)}`).digest("hex");
}

export function redactArguments(value: unknown, keys = ["apiKey", "api_key", "authorization", "password", "secret", "token"]): unknown {
  if (Array.isArray(value)) return value.map(item => redactArguments(item, keys));
  if (!value || typeof value !== "object") return value;
  const result: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
    result[key] = keys.some(secret => key.toLowerCase().includes(secret.toLowerCase())) ? "[redacted]" : redactArguments(item, keys);
  }
  return result;
}

export class ToolGuard {
  private readonly specs = new Map<string, ToolSpec>();
  private readonly calls = new Map<string, number>();
  private readonly failures = new Map<string, number>();
  private readonly open = new Set<string>();
  private readonly grants = new Map<string, ApprovalGrant>();
  private readonly maxCalls: number;
  private readonly maxFailures: number;
  private readonly approvalTtlMs: number;
  private readonly now: () => number;

  constructor(specs: ToolSpec[], options: GuardOptions = {}) {
    this.maxCalls = options.maxCallsPerRun ?? 8;
    this.maxFailures = options.maxFailures ?? 3;
    this.approvalTtlMs = options.approvalTtlMs ?? 30 * 60_000;
    this.now = options.now ?? Date.now;
    for (const spec of specs) this.register(spec);
  }

  register(spec: ToolSpec) {
    this.specs.set(spec.name, { ...spec });
  }

  spec(name: string): ToolSpec | undefined {
    return this.specs.get(name);
  }

  /** Starts a new run and clears the per-run call counters. */
  beginRun(runId: string) {
    this.calls.set(runId, 0);
    return runId;
  }

  decide(runId: string, call: ToolCall): GuardDecision {
    const spec = this.specs.get(call.name);
    if (!spec) return { effect: "deny", reason: `Unknown tool: ${call.name}`, code: "UNKNOWN_TOOL" };
    if (this.open.has(call.name)) return { effect: "deny", reason: `${call.name} circuit is open`, code: "CIRCUIT_OPEN" };
    const count = this.calls.get(runId) || 0;
    if (count >= this.maxCalls) return { effect: "deny", reason: `Per-run tool-call limit ${this.maxCalls} reached`, code: "CALL_LIMIT" };
    this.calls.set(runId, count + 1);
    const digest = callDigest(call);
    const needsApproval = spec.approval === "always" ||
      (spec.approval !== "never" && (spec.risk === "write" || spec.risk === "command" || spec.scope === "write"));
    if (!needsApproval) return { effect: "allow", spec };
    const grant = this.grants.get(call.id);
    if (grant && grant.tool === call.name && grant.digest === digest && grant.expiresAt >= this.now()) return { effect: "allow", spec };
    return { effect: "approval", spec, digest, reason: `${spec.risk} tool requires content-bound approval` };
  }

  approve(call: ToolCall): ApprovalGrant {
    const grant = { tool: call.name, digest: callDigest(call), expiresAt: this.now() + this.approvalTtlMs };
    this.grants.set(call.id, grant);
    return grant;
  }

  deny(callId: string) { this.grants.delete(callId); }

  record(spec: ToolSpec, success: boolean) {
    const failures = success ? 0 : (this.failures.get(spec.name) || 0) + 1;
    this.failures.set(spec.name, failures);
    if (failures >= this.maxFailures) this.open.add(spec.name);
    if (success && spec.idempotent) this.open.delete(spec.name);
    return { failures, open: this.open.has(spec.name) };
  }

  resetCircuit(name: string) {
    this.open.delete(name);
    this.failures.delete(name);
  }

  state() {
    return {
      openCircuits: [...this.open],
      calls: Object.fromEntries(this.calls),
      failures: Object.fromEntries(this.failures)
    };
  }
}
