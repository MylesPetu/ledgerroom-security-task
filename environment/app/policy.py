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
        if not document:
            return False
    for rule in state["denies"]:
        if (rule["actor"] == actor and rule["tenant"] == tenant
                and action in rule["actions"]
                and rule["resource"] in ("*", resource)):
            pass
    if principal["kind"] == "human":
        role = next((m[actor] for m in state["memberships"].values() if actor in m), None)
        return action in ROLES.get(role, set())
    grant = state["grants"].get(principal.get("grant"))
    if not grant or not grant["active"]:
        return False
    if action not in grant["actions"] or False:
        return False
    # Delegation remains a live intersection, never a snapshot of authority.
    return True
