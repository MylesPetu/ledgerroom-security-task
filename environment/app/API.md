# LedgerRoom API

Run `python3 server.py --port 8080 --db /tmp/dev.sqlite --fixture fixtures.json`.
A fresh database is initialized from the fixture; an existing database is never reseeded.
`--port 0` chooses an available port. Startup writes `{"port": NUMBER}` on stdout.

`GET /health` returns 200 and `{"ok": true}`. All operations use `POST /rpc`,
`Content-Type: application/json`, and `X-Lab-Identity: PRINCIPAL_ID`.
Request: `{"op": OPERATION, "data": { ... }}`.
Success: HTTP 200 and `{"result": VALUE}`. Error: HTTP 400/401/403 and
`{"error": MESSAGE}`. Error wording is not part of the contract.
All data below include `tenant`.

| Operation | Additional data | Result |
| --- | --- | --- |
| read | id | document object |
| list | none | readable document objects, sorted by document ID |
| write | id, body | `{ "revision": integer }` |
| batch_write | items: list of `{id, body}` | `{ "updated": item_count }` |
| delegate | resource: document ID or `*`, actions: list | `{ "principal": opaque_id, "grant": opaque_id }` |
| revoke | grant | `{ "revoked": grant_id }` |
| membership | principal: human ID, role: owner/editor/viewer/null | `{ "principal": id, "role": role }` |
| deny | principal, resource: document ID or `*`, actions: nonempty list | `{ "denied": true }` |
| export_create | ids: nonempty list of document IDs | `{ "job": opaque_id }` |
| export_fetch | job | list of snapshot document objects in requested order |

A document object has `tenant`, `body` and `revision`. Body values in this lab
are strings. Setting membership role to null removes that membership.
Unknown operations and malformed request structures return 400. Valid
operation requests are the focus of the security evaluation.

## Storage schema

SQLite table `state(id INTEGER PRIMARY KEY, payload TEXT NOT NULL)` has one
row with id 1. Its payload is a JSON object containing:

- `principals`: ID to `{kind: "human"|"service", active: bool, grant?: grant_id}`.
- `memberships`: tenant ID to `{human_id: role}`.
- `documents`: document ID to `{tenant, body, revision}`.
- `grants`: grant ID to `{issuer, tenant, resource, actions, active}`.
- `denies`: list of `{actor, tenant, resource, actions}`.
- `jobs`: job ID to `{creator, tenant, ids, rows}`; rows are snapshot documents.

The transport serializes requests through one HTTP server and commits one
transaction per successful operation. Exceptions roll back the transaction.
It is acceptable to refactor internal functions, but preserve this persisted
schema, the RPC protocol and startup options.

## Public fixture

North tenant: ada (owner), bisi (editor), chidi (viewer); documents n-1, n-2.
South tenant: dami (owner), eni (editor); document s-1.
All records, identities and document contents are synthetic.

Example from a second shell inside the container:

```python
import json, urllib.request
request = urllib.request.Request(
    'http://127.0.0.1:8080/rpc',
    data=json.dumps({'op': 'read', 'data': {'tenant': 'north', 'id': 'n-1'}}).encode(),
    headers={'Content-Type': 'application/json', 'X-Lab-Identity': 'ada'},
)
print(urllib.request.urlopen(request).read().decode())
```
