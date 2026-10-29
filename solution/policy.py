ACTIONS = {"read", "write", "export", "delegate"}
ROLES = {"owner": ACTIONS, "editor": {"read", "write", "export"}, "viewer": {"read"}}

def allowed(state, actor, tenant, action, resource, seen=None):
    seen = set() if seen is None else set(seen)
    if actor in seen or action not in ACTIONS:
        return False
    seen.add(actor)
    principal = state["principals"].get(actor)
    if not principal or not principal.get("active"):
        return False
    if resource != "*":
        document = state["documents"].get(resource)
        if not document or document["tenant"] != tenant:
            return False
    for rule in state["denies"]:
        if (rule["actor"] == actor and rule["tenant"] == tenant
                and action in rule["actions"]
                and rule["resource"] in ("*", resource)):
            return False
    if principal["kind"] == "human":
        role = state["memberships"].get(tenant, {}).get(actor)
        return action in ROLES.get(role, set())
    grant = state["grants"].get(principal.get("grant"))
    if not grant or not grant["active"] or grant["tenant"] != tenant:
        return False
    if action not in grant["actions"] or grant["resource"] not in ("*", resource):
        return False
    # Delegation remains a live intersection, never a snapshot of authority.
    return (allowed(state, grant["issuer"], tenant, "delegate", resource, seen)
            and allowed(state, grant["issuer"], tenant, action, resource, seen))
