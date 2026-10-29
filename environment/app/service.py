import copy
import uuid
from policy import ACTIONS, allowed

class APIError(Exception):
    def __init__(self, status, message):
        self.status, self.message = status, message

def require(condition, message="forbidden"):
    if not condition:
        raise APIError(403, message)

def execute(state, actor, op, data):
    tenant = data.get("tenant")
    def check(action, resource="*"):
        require(allowed(state, actor, tenant, action, resource))
    def owner():
        require(state["principals"].get(actor, {}).get("active")
                and state["principals"][actor]["kind"] == "human"
                and state["memberships"].get(tenant, {}).get(actor) == "owner")
    if op == "read":
        rid = data["id"]
        check("read", rid)
        return copy.deepcopy(state["documents"][rid])
    if op == "list":
        return [copy.deepcopy(doc) for rid, doc in sorted(state["documents"].items())
                if doc["tenant"] == tenant and allowed(state, actor, tenant, "read", rid)]
    if op == "write":
        rid = data["id"]
        check("write", rid)
        state["documents"][rid]["body"] = data["body"]
        state["documents"][rid]["revision"] += 1
        return {"revision": state["documents"][rid]["revision"]}
    if op == "batch_write":
        items = data["items"]
        for item in items:
            check("read", item["id"])
            state["documents"][item["id"]]["body"] = item["body"]
            state["documents"][item["id"]]["revision"] += 1
        return {"updated": len(items)}
    if op == "delegate":
        actions = data["actions"]
        scope = data["resource"]
        if not actions or not isinstance(actions, list) or any(a not in ACTIONS for a in actions):
            raise APIError(400, "invalid actions")
        check("read", scope)
        gid, pid = uuid.uuid4().hex, uuid.uuid4().hex
        state["grants"][gid] = {"issuer": actor, "tenant": tenant,
            "resource": scope, "actions": sorted(set(actions)), "active": True}
        state["principals"][pid] = {"kind": "service", "active": True, "grant": gid}
        return {"principal": pid, "grant": gid}
    if op == "revoke":
        gid = data["grant"]
        grant = state["grants"].get(gid)
        require(grant is not None and grant["tenant"] == tenant)
        if actor != grant["issuer"]:
            owner()
        else:
            require(state["principals"].get(actor, {}).get("active"))
        grant["active"] = False
        return {"revoked": gid}
    if op == "membership":
        owner()
        target, role = data["principal"], data["role"]
        if role not in (None, "owner", "editor", "viewer"):
            raise APIError(400, "invalid role")
        if state["principals"].get(target, {}).get("kind") != "human":
            raise APIError(400, "membership requires a human")
        if role is None:
            state["memberships"].setdefault(tenant, {}).pop(target, None)
        else:
            state["memberships"].setdefault(tenant, {})[target] = role
        return {"principal": target, "role": role}
    if op == "deny":
        owner()
        if (not data["actions"] or any(a not in ACTIONS for a in data["actions"])
                or data["principal"] not in state["principals"]):
            raise APIError(400, "invalid deny")
        if data["resource"] != "*" and state["documents"].get(data["resource"], {}).get("tenant") != tenant:
            raise APIError(400, "invalid resource")
        state["denies"].append({"actor": data["principal"], "tenant": tenant,
            "actions": data["actions"], "resource": data["resource"]})
        return {"denied": True}
    if op == "export_create":
        ids = data["ids"]
        if not ids:
            raise APIError(400, "empty export")
        for rid in ids:
            check("read", rid)
            check("export", rid)
        jid = uuid.uuid4().hex
        state["jobs"][jid] = {"creator": actor, "tenant": tenant, "ids": list(ids),
            "rows": [copy.deepcopy(state["documents"][rid]) for rid in ids]}
        return {"job": jid}
    if op == "export_fetch":
        job = state["jobs"].get(data["job"])
        require(job is not None)
        return copy.deepcopy(job["rows"])
    raise APIError(400, "unknown operation")
