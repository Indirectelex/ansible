# Mandatory change and teaching-note protocol

This is a fluidity process: documentation moves with the code. It is not a
separate audit performed after the system becomes confusing.

## Before editing

1. Identify the layer: inventory, collection, normalization, schema,
   publication, server, browser, styling, deployment, or test.
2. Read the file’s `TEACHER NOTE` and its linked guide chapter.
3. Trace the immediate producer and consumer.
4. State the observable finish line.
5. Select the smallest validation that can prove the change.

## While editing

Update the explanation in the same patch whenever any of these change:

- input command or external endpoint;
- registered Ansible fact or Python return shape;
- status rule or threshold;
- JSON key, schema version, or manifest entry;
- HTTP route or security condition;
- browser state, renderer, or action;
- CSS class used as a JavaScript contract;
- service command, environment variable, or file location.

Do not add comments that merely translate syntax into English. Explain the
reason, boundary, failure mode, and validation.

## Required in-file format

Small files need one opening block:

```text
TEACHER NOTE — CHAPTER <number/name>
Purpose: why this file exists.
Inputs: what it trusts or receives.
Outputs: what it produces and who consumes it.
Failure model: how absence, unknown evidence, or errors are represented.
CHANGE INSTRUCTIONS: what else must change and which test must run.
```

Long files also need internal chapter banners at meaningful transitions. A
chapter should group a concept, not an arbitrary number of lines.

## Generated files

These are evidence, not maintained source:

- `reports/manifest.json`;
- `reports/storage-topology.json`;
- `reports/<host>.json` and `.md`;
- `reports/maintenance/*.json`;
- published copies under `reports/assets/` and `reports/index.html`;
- private state under `.state/health_check/`.

Change their producer and regenerate them. Never make a lasting fix directly
inside a generated file.

## Cross-file change matrix

| Change | Also inspect |
| --- | --- |
| Inventory group | manifest publication, topology, action allowlist |
| Feature flag | discovery, policy, module include, report output |
| Collector command | parser/filter, failure handling, fixture tests |
| Module result | overall aggregation, dashboard reasons, renderer |
| Report field | schema task, JS consumer, Markdown template, tests |
| UI element ID/class | HTML, JS selectors, CSS, layout tests |
| HTTP route | server handler, JS fetch, security tests, operations guide |
| UniFi metric | fixed query list, normalization, rendering, server tests |
| systemd command | custom-server invariant, environment, runtime checks |

## Validation ladder

Use the lowest rung that proves the change, then run the complete unit suite.

1. Parse/syntax check.
2. Focused unit test.
3. Full unit suite.
4. Ansible syntax check.
5. Limited non-destructive playbook run.
6. Publish dashboard.
7. Functional HTTP checks.
8. Browser inspection.
9. Reboot/restart test when deployment changed.

## Handoff instructions

Every handoff must say:

- what changed;
- why it changed;
- which source files are authoritative;
- how to deploy or publish it;
- exact validation performed;
- any validation not available;
- rollback or recovery path if runtime behaviour changed.
