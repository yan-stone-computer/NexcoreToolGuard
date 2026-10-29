# Nexcore Tool Guard

> The policy layer around AI tool calls: risk-aware approval, exact-call binding, per-run budgets,
> argument redaction and circuit breaking.

This is the tool guard extracted from NexcoreWork's execution runtime. It has no model SDK and no
database. A host only needs a tool registry and a place to display approval requests.

## What it prevents

- a write command being approved once and then reused with different content;
- unlimited tool calls from a model loop;
- repeated calls to a failing tool;
- credentials appearing in process traces;
- dangerous tools running without an explicit approval policy.

## Usage

```ts
import { ToolGuard } from "nexcore-tool-guard";

const guard = new ToolGuard([
  {
    name: "read_file",
    scope: "read",
    risk: "read",
    timeoutMs: 5_000,
  },
  {
    name: "write_file",
    scope: "write",
    risk: "write",
    timeoutMs: 10_000,
  },
]);

guard.beginRun(runId);
const decision = guard.decide(runId, call);

if (decision.effect === "approval") {
  const approved = await askUser(decision.digest);
  if (approved) guard.approve(call);
}

const result = await execute(call);
guard.record(decision.spec, result.ok);
```

## Approval semantics

The approval digest covers the tool name and canonicalized arguments. The same call ID with a
different argument value is a different approval. Grants expire and are scoped to the exact call.

## Runtime semantics

- default call budget: 8 per run;
- default circuit threshold: 3 consecutive failures;
- an open circuit rejects future calls until reset;
- `scope === "read"` tools can run without approval;
- write, command and `approval: "always"` tools request approval;
- `redactArguments()` recursively replaces credential-like fields for traces.

## Composition

Use with:

- [NexcoreAgent](https://github.com/yan-stone-computer/NexcoreAgent)
- [nexcore-context-governor](https://github.com/yan-stone-computer/nexcore-context-governor)
- [NexcoreMemory](https://github.com/yan-stone-computer/NexcoreMemory)

The guard makes decisions; it does not execute tools and does not claim to be an OS sandbox.
Workspace path enforcement remains the host's responsibility.

## License

MIT.
