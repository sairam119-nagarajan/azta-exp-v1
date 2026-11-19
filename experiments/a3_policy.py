"""Operator-only A3 policy additions/transitions. No telemetry/trust-driven mutation."""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import secrets
from experiments.a3_mqtt import MQTTClient, ProbeError, pump_until, DEVICES, RECEIVER, topic, password_for
from experiments.foundation_run import FoundationConfig, runtime
from experiments.research_records import RunRecords, new_run_id

CONTROL = "$CONTROL/dynamic-security/v1"
PDP_ROLE = "azta-pdp-telemetry-read"
RECEIVER_ROLE = "azta-operations-read"


def roles(device):
    return (f"azta-{device}-telemetry-publish", f"azta-{device}-operation-publish")


def acl(kind, target):
    return dict(acltype=kind, topic=target, allow=True, priority=10)


def read_acls(target):
    return [acl(kind,target) for kind in ("subscribeLiteral", "publishClientReceive")]


def canonical(acls):
    return sorted(acls, key=lambda a: (a["acltype"], a["topic"], a["priority"], a["allow"]))


class Admin:
    def __init__(self, records):
        self.records = records
        self.counter = 0
        self.client = MQTTClient("admin", password_for("admin"),
                                lambda kind, **data: records.event("admin", kind, **data))
        if self.client.connect() != 0 or self.client.subscribe(CONTROL+"/response") != [1]:
            raise ProbeError("admin_connection_failed")

    def call(self, command, optional=False, **fields):
        self.counter += 1
        request_id = f"{self.records.config.run_id}:{self.counter}"
        safe = {key: value for key,value in fields.items() if key != "password"}
        self.records.event("admin","ADMIN_REQUEST",command=command,request_id=request_id,parameters=safe)
        payload = json.dumps({"commands":[dict(command=command,correlationData=request_id,**fields)]}).encode()
        info = self.client.publish(CONTROL,payload,1)
        pump_until([self.client],lambda: info.mid in self.client.acks,3)
        if self.client.acks.pop(info.mid) not in (0,16):
            raise ProbeError("admin_puback_denied")
        response = None
        def arrived():
            nonlocal response
            while self.client.messages:
                message = self.client.messages.pop(0)
                for value in json.loads(message.payload).get("responses",[]):
                    if value.get("correlationData") == request_id:
                        response = value
            return response is not None
        pump_until([self.client],arrived,3)
        success = "error" not in response
        self.records.event("admin","ADMIN_RESPONSE",command=command,request_id=request_id,success=success)
        if not success:
            # Values from responses never enter error/log text.
            if optional and "not found" in str(response["error"]).lower():
                return None
            raise ProbeError("admin_command_failed")
        return response.get("data",{})

    def client_metadata(self, identity, optional=False):
        result = self.call("getClient",optional=optional,username=identity)
        if result is None:
            return None
        data = result["client"]
        return dict(username=data["username"],clientid=data.get("clientid"),
                    disabled=data.get("disabled",False),
                    roles=sorted((dict(rolename=r["rolename"],priority=r.get("priority",-1))
                                  for r in data.get("roles",[])),key=lambda r:r["rolename"]),
                    groups=sorted(g["groupname"] for g in data.get("groups",[])))

    def role(self, name, optional=False):
        result = self.call("getRole",optional=optional,rolename=name)
        if result is None:
            return None
        return canonical([{key:a[key] for key in ("acltype","topic","allow","priority")}
                          for a in result["role"].get("acls",[])])

    def defaults(self):
        data = self.call("getDefaultACLAccess")["acls"]
        if {a["acltype"] for a in data} != {"publishClientSend","publishClientReceive","subscribe","unsubscribe"} or any(a["allow"] for a in data):
            raise ProbeError("unexpected_default_acl")
        return data

    def device(self, device):
        current = self.client_metadata(DEVICES[device])
        allowed = set(roles(device))
        actual = {r["rolename"] for r in current["roles"]}
        if current["clientid"] != DEVICES[device] or current["groups"] or not actual <= allowed or roles(device)[0] not in actual:
            raise ProbeError("unexpected_device_policy")
        for name,workload in zip(roles(device),("telemetry","operations")):
            if self.role(name) != [acl("publishClientSend",topic(device,workload))]:
                raise ProbeError("unexpected_device_acl")
        return current

    def mutation(self, command, before, verify, **fields):
        # A failed/ambiguous response still leaves restoration to the caller's finally.
        self.records.event("admin","MUTATION_PRECONDITION",command=command,expected_prestate=before)
        self.call(command,**fields)
        after = verify()
        self.records.event("admin","MUTATION_POSTCONDITION",command=command,verified_poststate=after)
        return after

    def expect_device(self, device, expected):
        actual = self.device(device)
        if actual != expected:
            raise ProbeError("policy_postcondition_mismatch")
        return actual

    def restrict(self, device):
        self.defaults()
        before = self.device(device)
        if before["disabled"] or {r["rolename"] for r in before["roles"]} != set(roles(device)):
            raise ProbeError("restrict_requires_full")
        after = dict(before,roles=[r for r in before["roles"] if r["rolename"] != roles(device)[1]])
        return self.mutation("removeClientRole",before,lambda:self.expect_device(device,after),
                             username=DEVICES[device],rolename=roles(device)[1])

    def quarantine(self, device):
        before = self.device(device)
        if before["disabled"] or [r["rolename"] for r in before["roles"]] != [roles(device)[0]]:
            raise ProbeError("quarantine_requires_restrict")
        after = dict(before,disabled=True)
        return self.mutation("disableClient",before,lambda:self.expect_device(device,after),
                             username=DEVICES[device])

    def restore(self, device, baseline):
        # Restore exactly the captured enabled FULL baseline, not a guessed/reset policy.
        if baseline["disabled"] or {r["rolename"] for r in baseline["roles"]} != set(roles(device)):
            raise ProbeError("invalid_restoration_baseline")
        current = self.device(device)
        missing = [r for r in baseline["roles"] if r not in current["roles"]]
        for role in missing:
            if role["rolename"] != roles(device)[1]:
                raise ProbeError("unexpected_restoration_difference")
            after = dict(current,roles=sorted(current["roles"]+[role],key=lambda r:r["rolename"]))
            current = self.mutation("addClientRole",current,lambda:self.expect_device(device,after),
                                    username=DEVICES[device],**role)
        if current["disabled"]:
            after = dict(current,disabled=False)
            current = self.mutation("enableClient",current,lambda:self.expect_device(device,after),
                                    username=DEVICES[device])
        self.expect_device(device,baseline)
        self.records.event("admin","RESTORATION_VERIFIED",target=DEVICES[device],state=baseline)

    @contextmanager
    def restored_test(self, device):
        self.defaults()
        baseline = self.device(device)
        # Test the no-op restore path before permitting a mutation.
        self.restore(device,baseline)
        try:
            yield baseline
        finally:
            try:
                self.restore(device,baseline)
            except Exception:
                self.records.event("admin","RESTORATION_FAILED",target=DEVICES[device],requires_operator=True)
                raise ProbeError("restoration_failed_STOP") from None

    def audit(self, expanded=True):
        result = dict(defaults=self.defaults(),device01=self.device("device01"))
        pdp = self.client_metadata("azta-pdp")
        if pdp["disabled"] or pdp["clientid"] != "azta-pdp" or pdp["groups"] or [r["rolename"] for r in pdp["roles"]] != [PDP_ROLE]:
            raise ProbeError("unexpected_pdp_policy")
        expected = read_acls(topic("device01","telemetry")) + [acl("unsubscribeLiteral",topic("device01","telemetry"))]
        if expanded:
            expected += read_acls(topic("device02","telemetry"))
        actual_pdp_acls = self.role(PDP_ROLE)
        self.records.event("admin","PDP_ACL_AUDIT",acls=actual_pdp_acls)
        if actual_pdp_acls != canonical(expected):
            raise ProbeError("unexpected_pdp_acl")
        result["pdp"] = pdp
        if expanded:
            result["device02"] = self.device("device02")
            receiver = self.client_metadata(RECEIVER)
            if receiver["disabled"] or receiver["groups"] or receiver["clientid"] != RECEIVER or [r["rolename"] for r in receiver["roles"]] != [RECEIVER_ROLE]:
                raise ProbeError("unexpected_receiver_policy")
            if self.role(RECEIVER_ROLE) != canonical(read_acls(topic("device01","operations"))+read_acls(topic("device02","operations"))):
                raise ProbeError("unexpected_receiver_acl")
            result["receiver"] = receiver
        self.records.event("admin","POLICY_AUDIT",policy=result)
        return result

    def provision(self, credential_root="/credentials"):
        existing = self.client_metadata("azta-device-02",optional=True)
        if existing is not None:
            self.audit()
            return "already_provisioned"
        self.audit(expanded=False)
        if self.client_metadata(RECEIVER,optional=True) is not None:
            raise ProbeError("partial_provisioning_STOP")
        specifications = {
            roles("device02")[0]: [acl("publishClientSend",topic("device02","telemetry"))],
            roles("device02")[1]: [acl("publishClientSend",topic("device02","operations"))],
            RECEIVER_ROLE: read_acls(topic("device01","operations"))+read_acls(topic("device02","operations")),
        }
        for name in specifications:
            if self.role(name,optional=True) is not None:
                raise ProbeError("unexpected_existing_role_STOP")
        passwords = {}
        for identity in ("azta-device-02",RECEIVER):
            path = Path(credential_root)/(identity+"-password")
            if not path.exists():
                fd = os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
                with os.fdopen(fd,"w") as stream:
                    stream.write(secrets.token_urlsafe(32)+"\n")
            passwords[identity] = path.read_text().strip()
            if len(passwords[identity]) < 32:
                raise ProbeError("invalid_local_credential")
        rollback = []
        try:
            for name,permissions in specifications.items():
                rollback.append(("deleteRole",dict(rolename=name)))
                def verify_role(n=name,p=permissions):
                    actual = self.role(n)
                    if actual != canonical(p):
                        raise ProbeError("new_role_mismatch")
                    return dict(rolename=n,acls=actual)
                self.mutation("createRole",dict(rolename=name,exists=False),verify_role,
                              rolename=name,acls=permissions)
            for identity,names in (("azta-device-02",roles("device02")),(RECEIVER,[RECEIVER_ROLE])):
                rollback.append(("deleteClient",dict(username=identity)))
                expected = dict(username=identity,clientid=identity,disabled=False,groups=[],
                    roles=sorted([dict(rolename=n,priority=10) for n in names],key=lambda r:r["rolename"]))
                def verify_client(i=identity,e=expected):
                    actual = self.client_metadata(i)
                    if actual != e:
                        raise ProbeError("new_client_mismatch")
                    return actual
                self.mutation("createClient",dict(username=identity,exists=False),verify_client,
                              username=identity,clientid=identity,password=passwords[identity],
                              roles=expected["roles"])
            current = self.role(PDP_ROLE)
            for permission in read_acls(topic("device02","telemetry")):
                rollback.append(("removeRoleACL",dict(rolename=PDP_ROLE,acltype=permission["acltype"],topic=permission["topic"])))
                expected = canonical(current+[permission])
                def verify_pdp(e=expected):
                    actual = self.role(PDP_ROLE)
                    if actual != e:
                        raise ProbeError("pdp_extension_mismatch")
                    return dict(rolename=PDP_ROLE,acls=actual)
                self.mutation("addRoleACL",dict(rolename=PDP_ROLE,acls=current),verify_pdp,
                              rolename=PDP_ROLE,**permission)
                current = expected
            self.audit()
            return "provisioned"
        except Exception:
            failures = 0
            for command,parameters in reversed(rollback):
                try:
                    self.records.event("admin","ROLLBACK_PRECONDITION",command=command,created_by_this_transaction=True)
                    self.call(command,optional=True,**parameters)
                    self.records.event("admin","ROLLBACK_RESPONSE",command=command,success=True)
                except Exception:
                    failures += 1
            self.records.event("admin","PROVISION_ROLLBACK",failures=failures)
            if failures:
                raise ProbeError("provision_restoration_failed_STOP") from None
            self.audit(expanded=False)
            raise

    def close(self):
        self.client.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action",choices=("inspect","provision"))
    parser.add_argument("--run-id",default=None)
    args = parser.parse_args()
    config = FoundationConfig(args.run_id or new_run_id(),scenario="a3-policy")
    records = RunRecords("/results",config,runtime(),streams=("admin",))
    admin = None
    try:
        admin = Admin(records)
        if args.action == "provision":
            result = admin.provision()
        else:
            result = admin.audit(expanded=admin.client_metadata("azta-device-02",optional=True) is not None)
        records.finish(dict(state="COMPLETE",result=result))
        print("A3_POLICY PASS",args.action,config.run_id)
        return 0
    except Exception as exc:
        code = str(exc) if isinstance(exc,ProbeError) else "internal_error"
        records.finish(dict(state="INCOMPLETE",failure_code=code))
        print("A3_POLICY FAILED",code)
        return 1
    finally:
        if admin:
            admin.close()
        records.close()


if __name__ == "__main__":
    raise SystemExit(main())
