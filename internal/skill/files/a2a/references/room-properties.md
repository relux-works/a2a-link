# Typed room properties

Use the owner-approved selected own identity and connection. These source
commands do not authorize a live mutation or installation by themselves.

```text
a2a room avatar get ROOM [--json]
a2a room avatar set ROOM --expect-room-id !ID --mxc MXC [--json]
a2a room parent get CHILD --parent PARENT [--json]
a2a room parent set CHILD --parent PARENT --expect-child-id !CHILD --expect-parent-id !PARENT --via SERVER [--via SERVER...] --canonical true|false [--json]
```

Resolve aliases once without redirects. Sets require explicit matching expected
room IDs, including for opaque ID inputs. Avatar set uses an existing MXC URI
and the fixed empty `m.room.avatar` key; it never uploads or checks media.
Parent set changes only the child's `m.space.parent` key for the distinct
parent ID, preserving explicit server order/case and canonical true/false.
It creates no reciprocal link, joins no room, and changes no connection config.

Version 1 JSON/text distinguishes a bounded write ACK from VERIFIED full-content
readback. An uncertain response is UNKNOWN with any known event ID retained;
never repeat set as a blind retry. A separately authorized get can inspect the
exact key. A pre-operation refusal prints no operation result. ABSENT is a
validated exact-key not-found response, not proof that the room exists.

The complete input, refusal and readback contract is in the repository's
`docs/cli.md`, under “Typed room properties”. No installed adoption is implied.
