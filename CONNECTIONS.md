# Connection checks and session fixes

A resolver answering a DNS or MTU probe does not prove that a Vortex server
session was accepted. The server `selfcheck` command checks both stages:

```bash
sudo vortex-server selfcheck --config /etc/vortex-server/server.toml
sudo vortex-server selfcheck --config /etc/vortex-server/server.toml --public
sudo journalctl -u vortex-server -n 100 --no-pager
```

Use the actual configuration path if it differs. A local pass with a public
failure points to a difference in the external DNS path; inspect delegation,
firewalls, and the resolver used by the phone. A `server session table is full`
error identifies capacity exhaustion. Do not rotate a working key as a routine
connection fix: existing client configurations depend on it. Avoid sharing
configuration links, encryption keys, or unsanitized query names in diagnostics.

The public server source includes two concurrency fixes without wire-format
changes:

- Initialize the stream cleanup callback before publishing a new session.
  Duplicate concurrent `SESSION_INIT` requests now reuse that initialized record.
- Validate a `SESSION_CLOSE` cookie while holding the same lock that removes
  its session. Previously a worker could validate an old session, then close a
  new session that reused the same ID after cleanup. Cookie validation and
  removal now happen atomically.

Regression checks reproduce the stale-close interleaving on the previous code
and verify that the replacement session survives with the fix. Another test
sends 64 concurrent initialization retries in each response mode (raw and
Base64), parses every acceptance, and checks that only one session is created.
The server command also tests a successful MTU probe followed by a failed
session acceptance and must report failure.

These local tests do not establish the cause of a particular phone connection
failure. An Android device, its configured resolver, authoritative public DNS,
and the actual VPS still require end-to-end verification. The public repository
contains server source only.
