"""Finite operator-run A3 live matrix, isolation, transitions and restoration."""
import argparse
import json
import time
from dataclasses import replace
from experiments.a3_mqtt import DEVICES, RECEIVER, MQTTClient, ProbeError, topic, password_for, pump_until, observe_window
from experiments.a3_policy import Admin
from experiments.foundation_run import FoundationConfig, run, runtime
from experiments.research_records import RunRecords, encode_payload, digest, new_run_id, utc_now


class StateProof:
    def __init__(self, records, admin):
        self.records, self.admin = records, admin
        self.clients = {}
        self.sequence = 0
        self.receipts = []

    def connect(self, identity, expected=0):
        stream = "receiver" if identity == RECEIVER else "pdp" if identity == "azta-pdp" else "publisher"
        client = MQTTClient(identity,password_for(identity),
                            lambda kind,**v:self.records.event(stream,kind,**v))
        if client.connect() != expected:
            client.close()
            raise ProbeError("unexpected_connack")
        return client

    def start(self):
        for identity in ("azta-pdp",RECEIVER,*DEVICES.values()):
            self.clients[identity] = self.connect(identity)
        for device in DEVICES:
            for identity,workload in (("azta-pdp","telemetry"),(RECEIVER,"operations")):
                if self.clients[identity].subscribe(topic(device,workload)) != [1]:
                    raise ProbeError("exact_subscription_failed")

    def drain(self):
        for identity in ("azta-pdp",RECEIVER):
            client=self.clients[identity]
            while client.messages:
                message=client.messages.pop(0)
                try:
                    data=json.loads(message.payload)
                    if data.get("run_id") != self.records.config.run_id:
                        continue
                    if type(data.get("sequence")) is not int:
                        raise ValueError()
                    receipt=dict(sequence=data["sequence"],topic=message.topic,
                        qos=message.qos,payload_sha256=digest(message.payload),
                        claimed_device_id=data.get("device_id"),claimed_run_id=data["run_id"],
                        local_session_id=client.session_id,identity=identity,
                        authenticated_publisher_identity=None,decision="NOT_IMPLEMENTED")
                except (ValueError,AttributeError):
                    raise ProbeError("malformed_probe_receipt") from None
                self.receipts.append(receipt)
                stream="receiver" if identity==RECEIVER else "pdp"
                self.records.event(stream,"RECEIVER_OBSERVED" if stream=="receiver" else "PDP_OBSERVED",**receipt)

    def publish(self, device, destination, workload, allowed=True, phase="full"):
        self.sequence+=1
        seq=self.sequence
        client=self.clients[DEVICES[device]]
        cfg=FoundationConfig(self.records.config.run_id,device_identity=DEVICES[device],
            claimed_device_id=device,topic=topic(device,workload),workload=workload,message_count=1000)
        payload=encode_payload(cfg,seq,client.session_id,utc_now())
        target=topic(destination,workload)
        self.records.event("publisher","PROBE_ATTEMPT",phase=phase,identity=client.identity,
            local_session_id=client.session_id,sequence=seq,topic=target,qos=1,payload_sha256=digest(payload))
        info=client.publish(target,payload,1)
        pump_until(list(self.clients.values()),lambda:info.mid in client.acks,3)
        ack=client.acks.pop(info.mid)
        self.records.event("publisher","PROBE_PUBACK",phase=phase,identity=client.identity,
            sequence=seq,topic=target,reason_code=ack)
        if ack != (0 if allowed else 135):
            raise ProbeError("unexpected_probe_puback")
        def received():
            self.drain()
            return any(r["sequence"]==seq and r["topic"]==target and r["payload_sha256"]==digest(payload)
                       for r in self.receipts)
        if allowed:
            pump_until(list(self.clients.values()),received,3)
        else:
            observe_window(list(self.clients.values()),0.2)
            if received():
                raise ProbeError("denied_publication_delivered")
        self.records.event("publisher","PROBE_VERIFIED",phase=phase,identity=client.identity,
            sequence=seq,topic=target,allowed=allowed,actual_receipt=allowed,reason_code=ack)

    def isolation(self, phase):
        for device,other in (("device01","device02"),("device02","device01")):
            for workload in ("operations","telemetry"):
                self.publish(device,other,workload,False,phase)
            if self.clients[DEVICES[device]].subscribe("azta/devices/#") != [135]:
                raise ProbeError("broad_subscription_allowed")
        # Reader privileges are receive-only and do not include administration.
        for identity,forbidden in ((RECEIVER,topic("device01","telemetry")),
                                   ("azta-pdp",topic("device01","operations"))):
            client=self.clients[identity]
            if client.subscribe(forbidden) != [135]:
                raise ProbeError("reader_cross_purpose_subscription_allowed")
            info=client.publish(topic("device01","operations"),b"nonsecret-negative-probe",1)
            pump_until(list(self.clients.values()),lambda:info.mid in client.acks,3)
            if client.acks.pop(info.mid) != 135:
                raise ProbeError("reader_publish_allowed")

    def target_cycle(self, target, control):
        target_id,control_id=DEVICES[target],DEVICES[control]
        control_session=self.clients[control_id].session_id
        control_policy=self.admin.device(control)
        with self.admin.restored_test(target):
            for device in (target,control):
                for workload in ("telemetry","operations"):
                    self.publish(device,device,workload,True,"FULL_ACCESS")
            self.clients[target_id].close()
            self.admin.restrict(target)
            self.clients[target_id]=self.connect(target_id)
            self.publish(target,target,"telemetry",True,"RESTRICT")
            self.publish(target,target,"operations",False,"RESTRICT")
            self.publish(control,control,"operations",True,"RESTRICT_CONTROL")
            live=self.clients[target_id]
            if not live.connected or live.connack != 0 or live.disconnection is not None:
                raise ProbeError("target_session_not_known_live")
            before=self.records.elapsed_ms()
            self.records.event("publisher","QUARANTINE_PRE_SESSION",
                target=target_id,client_id=target_id,local_session_id=live.session_id,
                connected=True,successful_connack=0)
            self.admin.quarantine(target)
            pump_until(list(self.clients.values()),lambda:live.disconnection is not None,3,allow_disconnect=True)
            if live.disconnection["intentional"]:
                raise ProbeError("unrelated_intentional_disconnect")
            self.records.event("publisher","TARGET_TERMINATION_CORRELATED",
                target=target_id,client_id=target_id,local_session_id=live.session_id,
                action_window_start_ms=before,observed_end_ms=self.records.elapsed_ms(),
                **live.disconnection,
                conclusion="known_target_session_ended_after_disable_action; no broker-log origin inference")
            rejected=self.connect(target_id,expected=135)
            rejected.close()
            # Remove dead target only from the event-pump set, not from broker policy.
            del self.clients[target_id]
            self.records.event("publisher","QUARANTINE_RECONNECT_DENIED",target=target_id,
                reason_code=135,telemetry_available=False,operations_available=False)
            for workload in ("telemetry","operations"):
                self.publish(control,control,workload,True,"QUARANTINE_CONTROL")
            if self.clients[control_id].session_id != control_session or not self.clients[control_id].connected:
                raise ProbeError("control_session_disrupted")
            if self.admin.device(control) != control_policy:
                raise ProbeError("control_policy_changed")
            self.records.event("publisher","UNAFFECTED_CONTROL",identity=control_id,
                local_session_id=control_session,connected=True,policy_unchanged=True)
        self.clients[target_id]=self.connect(target_id)
        for workload in ("telemetry","operations"):
            self.publish(target,target,workload,True,"RESTORE")
        self.publish(target,control,"operations",False,"RESTORE_ISOLATION")
        self.records.event("publisher","TARGET_CYCLE_PASS",target=target_id)

    def close(self):
        for client in self.clients.values():
            client.close()


def matrix(root, prefix):
    results=[]
    for device in DEVICES:
        for workload in ("telemetry","operations"):
            for qos in (0,1):
                cfg=FoundationConfig(f"{prefix}-{device}-{workload}-q{qos}",scenario="a3-matrix",
                    device_identity=DEVICES[device],claimed_device_id=device,
                    topic=topic(device,workload),workload=workload,qos=qos,
                    message_count=3,interval=0.1,timeout=8,seed=7)
                result=run(cfg,root)
                if result["incomplete"] or result["correlated_sequences"] != [1,2,3]:
                    raise ProbeError("research_matrix_failed")
                results.append(dict(run_id=cfg.run_id,counts=result["counts"]))
    return results


def failures(root,prefix):
    cases=[
        ("receiver-unavailable","operations","device01",1,dict(receiver_host="127.0.0.1"),"broker_unavailable"),
        ("device02-unavailable","telemetry","device02",1,dict(publisher_host="127.0.0.1"),"broker_unavailable"),
        ("qos0-nonarrival","operations","device01",0,dict(receiver_enabled=False),"timeout"),
    ]
    results=[]
    for name,workload,device,qos,options,expected in cases:
        cfg=FoundationConfig(f"{prefix}-{name}",scenario="a3-negative",
            device_identity=DEVICES[device],claimed_device_id=device,
            topic=topic(device,workload),workload=workload,qos=qos,
            message_count=2,interval=0,timeout=0.6)
        result=run(cfg,root,**options)
        if not result["incomplete"] or result["failure_code"] != expected:
            raise ProbeError("failure_case_misreported")
        if qos==0 and (result["counts"]["accepted_acknowledgements"] is not None or result["correlated_sequences"]):
            raise ProbeError("qos0_false_ack_or_receipt")
        results.append(dict(run_id=cfg.run_id,failure_code=result["failure_code"],counts=result["counts"]))
    return results


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-id",default=None)
    parser.add_argument("--output-dir",default="/results")
    args=parser.parse_args()
    prefix=args.run_id or ("a3-"+new_run_id()[4:16])
    cfg=FoundationConfig(prefix,scenario="a3-state-regression").validate()
    records=RunRecords(args.output_dir,cfg,runtime(),streams=("admin","publisher","pdp","receiver"))
    admin=proof=None
    summary=dict(state="INCOMPLETE",restoration_verified=False)
    baseline=None
    try:
        admin=Admin(records)
        baseline=admin.audit()
        for device in DEVICES:
            admin.restore(device,baseline[device])
        summary["matrix"]=matrix(args.output_dir,prefix)
        summary["failure_tests"]=failures(args.output_dir,prefix)
        proof=StateProof(records,admin)
        proof.start()
        proof.isolation("INITIAL_ISOLATION")
        proof.target_cycle("device01","device02")
        proof.target_cycle("device02","device01")
        proof.isolation("FINAL_ISOLATION")
        if admin.audit()!=baseline:
            raise ProbeError("final_policy_differs")
        summary.update(state="COMPLETE",restoration_verified=True)
    except Exception as exc:
        summary["failure_code"]=str(exc) if isinstance(exc,ProbeError) else "internal_error"
    finally:
        if proof:
            proof.close()
        if admin:
            # Fallback restoration for any failed phase; each operation verifies pre/post.
            if baseline:
                errors=[]
                for device in DEVICES:
                    try:
                        admin.restore(device,baseline[device])
                    except Exception:
                        errors.append(device)
                summary["restoration_verified"]=not errors
                if errors:
                    summary.update(state="INCOMPLETE",restoration_failures=errors,
                                   failure_code="restoration_failed_STOP")
            admin.close()
        records.finish(summary)
        records.close()
    print("A3_REGRESSION",summary["state"],"restoration_verified="+str(summary["restoration_verified"]),
          summary.get("failure_code",""))
    return int(summary["state"]!="COMPLETE")


if __name__=="__main__":
    raise SystemExit(main())
