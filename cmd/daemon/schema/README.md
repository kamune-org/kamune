# Daemon Protocol — JSON Schemas

Machine-readable schemas for the daemon's JSON-over-stdio protocol
(see [`docs/DAEMON.md`](../../docs/DAEMON.md) for the human-readable spec).

## Structure

```
schema/
  _shared/                 Reusable object schemas ($ref targets)
    command-envelope.schema.json
    event-envelope.schema.json
    session-info.schema.json
    relay-token.schema.json
  commands/<cmd>.schema.json   Validates the params object for each command
  events/<evt>.schema.json     Validates the data object for each event
```

Command and event schemas validate only the `params` / `data` payload — not
the full envelope. Use the envelope schemas to validate the wire format, then
dispatch to the command/event schema for the body.

## Usage

```js
// TypeScript / ajv example
import commandEnvelope from "./_shared/command-envelope.schema.json";
import startServer from "./commands/start_server.schema.json";

// validate full wire format
ajv.validate(commandEnvelope, wireMessage);

// validate params after extracting message.params
ajv.validate(startServer, wireMessage.params);
```

## Conventions

- **JSON Schema Draft 2020-12**
- `duration` fields serialize as `int64` nanoseconds (Go `time.Duration`), named `*_ns`
- `time` fields serialize as RFC3339 strings
- `enum` values mirror Go `const` blocks in `main.go` and `param.go`
- Schemas are derived from Go struct `json:` tags — keep them in sync when
  modifying param or event structs

## Coverage

All 51 commands and 25 push events documented in DAEMON.md have schemas.
