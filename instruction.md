# Recover tenant boundaries in LedgerRoom

LedgerRoom is a fictional document service used by several organisations. An incident review found that users could cross organisation boundaries, delegated identities retained revoked permissions, and queued exports bypassed later access changes. Repair the application in `/app` so every operation obeys the contract below while legitimate workflows continue to work. The included incident notes and traffic are synthetic.

The service runs on Python's standard library and SQLite. Preserve its HTTP interface, command-line options, persisted state schema and response shapes. You may refactor the implementation and add local tests. Do not replace the service with fixture-specific responses. Evaluation uses fresh data, different identities and document names, and sequences of operations in the same process and after restart.

## Identity and authorization contract

`X-Lab-Identity` is an already authenticated principal supplied by a trusted gateway. In this lab it is a fixture label, not a secret. Gateway authentication and identity-header spoofing are outside scope. Missing identity returns 401. Unknown and inactive principals cannot access documents or administer permissions.

Every data request supplies a tenant. A document must belong to that tenant, and the principal must have authority in that tenant. Membership in another tenant grants no authority. Missing documents and forbidden operations return 403 without document contents.

Human membership roles are tenant-specific:

| Role | Allowed document actions |
| --- | --- |
| owner | read, write, export, delegate |
| editor | read, write, export |
| viewer | read |

Explicit denies override role and delegated allows. A deny applies to one principal, tenant, a set of actions and either one document or `*`. Each action is independent: export does not imply read. Listings return only readable documents in the requested tenant; a valid principal with no readable documents receives an empty list.

A delegated service principal is backed by a grant with an issuer, tenant, document scope (`*` or one document), action set and active flag. To issue a grant, a principal must currently hold `delegate` and every requested action for the requested scope. Wildcard grants remain subject to per-document inherited denies when exercised. The action set must be a nonempty list of the four documented actions; invalid action sets return 400. A document-scoped grant cannot issue a wildcard or sibling-document grant. Service principals may issue narrower descendants when they have authority to delegate.

On EVERY use of a service principal, intersect its grant with the issuer's CURRENT authority, recursively through the whole chain. The issuer must still hold both `delegate` and the action being exercised for that document. Revoked grants, inactive ancestors, membership removal/downgrade and new denies take effect on the next request, including for descendants. Missing grant references and cycles must deny access rather than crash or authorize it.

Only an active human owner in the specified tenant may modify memberships or add denies. These are administrative operations, distinct from the four document actions. A service principal cannot receive a human membership role. A grant may be revoked by its active issuer or an active human owner of the grant's tenant; unrelated principals and owners from other tenants cannot revoke it.

## Operations and transaction requirements

The full request and response contract is in `/app/API.md`.

- `read`, `list` and `write` must enforce the same policy. Successful writes increment the document revision once.
- `batch_write` requires write authority for EVERY item. If any item fails, return 403 and change no document, revision or other state.
- `export_create` requires both read and export for every document, rejects an empty list with 400, and stores an immutable content snapshot. Mixed-tenant requests must be denied.
- `export_fetch` requires the original creator, the original tenant, and CURRENT read and export authority over every source document. A job ID is not an access credential. Fetching after a write returns the original snapshot; fetching after revocation or a relevant deny returns 403 without any rows.
- Permission changes and successful writes must survive a server restart. Preserve the SQLite transaction boundary so denied operations do not partially commit changes.

Start a disposable instance with `python3 /app/server.py --port 8080 --db /tmp/dev.sqlite --fixture /app/fixtures.json`. The server binds to loopback and prints its actual port as one JSON line. The verifier starts its own instances; leaving a process running is not required. Use only this isolated synthetic environment. No external services, real accounts or cloud credentials are needed.
