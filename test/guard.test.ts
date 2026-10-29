import assert from "node:assert/strict";
import test from "node:test";
import { ToolGuard, callDigest, redactArguments } from "../src/index.ts";

const write = { name: "write_file", scope: "write" as const, risk: "write" as const, timeoutMs: 1000 };

test("approval binds to the exact call payload", () => {
  const guard = new ToolGuard([write], { now: () => 1000, approvalTtlMs: 1000 });
  const call = { id: "c1", name: "write_file", arguments: { path: "a.md", content: "safe" } };
  const first = guard.decide("run", call);
  assert.equal(first.effect, "approval");
  guard.approve(call);
  assert.equal(guard.decide("run", call).effect, "allow");
  const changed = { ...call, arguments: { path: "a.md", content: "changed" } };
  assert.equal(guard.decide("run", changed).effect, "approval");
  assert.notEqual(callDigest(call), callDigest(changed));
});

test("expired approval no longer applies", () => {
  let now = 1000;
  const guard = new ToolGuard([write], { now: () => now, approvalTtlMs: 100 });
  const call = { id: "c1", name: "write_file", arguments: { path: "a.md" } };
  guard.approve(call);
  now = 1200;
  assert.equal(guard.decide("run", call).effect, "approval");
});

test("per-run call budget and circuit breaker denials are explicit", () => {
  const read = { name: "read_file", scope: "read" as const, risk: "read" as const, timeoutMs: 1000 };
  const guard = new ToolGuard([read, write], { maxCallsPerRun: 2, maxFailures: 2 });
  assert.equal(guard.decide("run", { id: "1", name: "read_file", arguments: {} }).effect, "allow");
  assert.equal(guard.decide("run", { id: "2", name: "write_file", arguments: {} }).effect, "approval");
  assert.equal(guard.decide("run", { id: "3", name: "read_file", arguments: {} }).effect, "deny");
  guard.record(read, false);
  assert.equal(guard.record(read, false).open, true);
  assert.equal(guard.decide("next", { id: "4", name: "read_file", arguments: {} }).code, "CIRCUIT_OPEN");
  guard.resetCircuit("read_file");
  assert.equal(guard.decide("next", { id: "5", name: "read_file", arguments: {} }).effect, "allow");
});

test("sensitive arguments can be recursively redacted for traces", () => {
  assert.deepEqual(redactArguments({ apiKey: "secret", nested: { Authorization: "Bearer x", path: "a.md" } }), {
    apiKey: "[redacted]",
    nested: { Authorization: "[redacted]", path: "a.md" }
  });
});
