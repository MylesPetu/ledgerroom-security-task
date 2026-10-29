# Synthetic incident brief: LedgerRoom

All names and records in this exercise were invented for this evaluation.
The traffic file records illustrative requests reproduced against the
vulnerable release. It is evidence to investigate, not an exhaustive bug list.

Support observed a South owner reading North records and a read-only North
user creating a more powerful service identity. A North export also remained
retrievable by another principal after the grant involved had been revoked.
A bulk-edit request unexpectedly changed records despite insufficient access.

The release added service-account delegation and queued export support to a
previously human-only service. The existing role data is authoritative;
removing useful roles, deleting tenant data, disabling exports or denying all
service principals would break the product's required behaviour.

Recover the authorization boundary across every affected route and verify
that subsequent permission changes take effect without restarting the app.
