'''Finite, operator-invoked Gate 4 probes; no automatic policy decisions.'''
import argparse
from datetime import datetime, timezone
import json
import time

import paho.mqtt.client as mqtt
from devices.mqtt_runtime import Session, TOPIC, log

DEVICE = 'azta-device-01'
TELEMETRY_ROLE = 'azta-device01-telemetry-publish'
OPERATION_ROLE = 'azta-device01-operation-publish'
OPERATION_TOPIC = 'azta/devices/device01/operations'
CONTROL = '$CONTROL/dynamic-security/v1'
OPERATION_ACL = dict(acltype='publishClientSend', topic=OPERATION_TOPIC,
                     allow=True, priority=10)


def utc():
    return datetime.now(timezone.utc).isoformat()


class Probe(Session):
    def __init__(self, identity, run_id, phase):
        super().__init__(identity)
        self.run_id = run_id
        self.phase = phase
        self.acks = {}
        self.subacks = {}
        self.responses = []
        self.request_id = 0
        self.client.on_publish = self.published
        self.client.on_subscribe = self.subscribed
        self.client.on_message = self.received

    def emit(self, event, **fields):
        log(event, run_id=self.run_id, phase=self.phase, observed_at=utc(), **fields)

    def published(self, client, userdata, mid, reason, properties):
        self.acks[mid] = reason.value

    def subscribed(self, client, userdata, mid, reasons, properties):
        self.subacks[mid] = [reason.value for reason in reasons]

    def received(self, client, userdata, message):
        if message.topic == CONTROL + '/response':
            self.responses.extend(json.loads(message.payload).get('responses', []))

    def subscribe(self, topic, expected):
        rc, mid = self.client.subscribe(topic, qos=1)
        if rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError('Subscribe enqueue failed')
        self.until(lambda: mid in self.subacks, 5)
        reasons = self.subacks.pop(mid)
        self.emit('suback', identity=self.identity, topic=topic, reason_codes=reasons)
        if reasons != [expected]:
            raise RuntimeError('Unexpected SUBACK')

    def publish(self, topic, payload, expected):
        info = self.client.publish(topic, json.dumps(payload), qos=1, retain=False)
        if info.rc != mqtt.MQTT_ERR_SUCCESS:
            raise RuntimeError('Publish enqueue failed')
        if topic != CONTROL:
            self.emit('publish_sent', identity=self.identity, topic=topic, qos=1,
                      payload=payload)
        self.until(lambda: info.mid in self.acks, 5)
        reason = self.acks.pop(info.mid)
        self.emit('puback', identity=self.identity, topic=topic, qos=1,
                  reason_code=reason, sequence=payload.get('sequence'))
        if reason not in expected:
            raise RuntimeError('Unexpected PUBACK')

    def control(self, command, optional=False, **fields):
        self.request_id += 1
        correlation = f'{self.run_id}:{self.phase}:{self.request_id}:{command}'
        request = dict(command=command, correlationData=correlation, **fields)
        self.emit('admin_request', command=command, request_id=correlation,
                  parameters=fields)
        self.publish(CONTROL, dict(commands=[request]), (0, 16))
        self.until(lambda: any(r.get('correlationData') == correlation
                              for r in self.responses), 5)
        response = next(r for r in self.responses
                        if r.get('correlationData') == correlation)
        self.responses.remove(response)
        success = 'error' not in response
        self.emit('admin_response', command=command, request_id=correlation,
                  success=success)
        if not success and not optional:
            raise RuntimeError(f'Administrative command rejected: {command}')
        return response

    def client_metadata(self, username):
        data = self.control('getClient', username=username)['data']['client']
        metadata = dict(username=data['username'], clientid=data.get('clientid'),
                        disabled=data.get('disabled', False),
                        roles=sorted(r['rolename'] for r in data.get('roles', [])),
                        groups=sorted(g['groupname'] for g in data.get('groups', [])))
        self.emit('client_metadata', **metadata)
        return metadata

    def role(self, name, optional=False):
        response = self.control('getRole', optional=optional, rolename=name)
        if 'error' in response:
            return None
        acls = response['data']['role'].get('acls', [])
        safe = [{k: acl[k] for k in ('acltype', 'topic', 'allow', 'priority')}
                for acl in acls]
        self.emit('role_metadata', rolename=name, acls=safe)
        return safe

    def audit(self):
        data = self.control('getDefaultACLAccess')['data']
        defaults = data['acls']
        self.emit('default_acl_metadata', defaults=defaults)
        expected = {'publishClientSend', 'publishClientReceive', 'subscribe', 'unsubscribe'}
        if not isinstance(defaults, list):
            raise RuntimeError('Unexpected default ACL response shape')
        if ({a['acltype'] for a in defaults} != expected
                or any(a['allow'] is not False for a in defaults)):
            raise RuntimeError('Expected all four deny defaults')
        device = self.client_metadata(DEVICE)
        pdp = self.client_metadata('azta-pdp')
        if (device['groups'] or device['clientid'] != DEVICE
                or not set(device['roles']) <= {TELEMETRY_ROLE, OPERATION_ROLE}
                or TELEMETRY_ROLE not in device['roles']):
            raise RuntimeError('Unexpected device role/group/client-ID configuration')
        if (pdp['groups'] or pdp['roles'] != ['azta-pdp-telemetry-read']
                or pdp['disabled']):
            raise RuntimeError('Unexpected PDP configuration')
        expected_acl = dict(acltype='publishClientSend', topic=TOPIC,
                            allow=True, priority=10)
        if self.role(TELEMETRY_ROLE) != [expected_acl]:
            raise RuntimeError('Unexpected diagnostic permissions')
        if OPERATION_ROLE in device['roles'] and self.role(OPERATION_ROLE) != [OPERATION_ACL]:
            raise RuntimeError('Unexpected operational permissions')
        return device


def administer(session, action):
    session.connect()
    session.subscribe(CONTROL + '/response', 1)
    before = session.audit()
    if action == 'prepare':
        acl = session.role(OPERATION_ROLE, optional=True)
        if acl is None:
            session.control('createRole', rolename=OPERATION_ROLE, acls=[OPERATION_ACL])
        elif acl != [OPERATION_ACL]:
            raise RuntimeError('Existing operational role differs; refusing to overwrite')
    if action in ('prepare', 'restore'):
        if session.role(OPERATION_ROLE) != [OPERATION_ACL]:
            raise RuntimeError('Normal operational role is missing or unexpected')
        if OPERATION_ROLE not in before['roles']:
            session.control('addClientRole', username=DEVICE,
                            rolename=OPERATION_ROLE, priority=10)
        session.control('enableClient', username=DEVICE)
    elif action == 'restrict':
        if OPERATION_ROLE not in before['roles']:
            raise RuntimeError('Expected FULL_ACCESS before RESTRICT')
        session.control('removeClientRole', username=DEVICE, rolename=OPERATION_ROLE)
    elif action == 'quarantine':
        if before['roles'] != [TELEMETRY_ROLE] or before['disabled']:
            raise RuntimeError('Expected enabled RESTRICT client before QUARANTINE')
        session.control('disableClient', username=DEVICE)
    after = session.audit()
    if action in ('prepare', 'restore'):
        valid = not after['disabled'] and set(after['roles']) == {TELEMETRY_ROLE, OPERATION_ROLE}
    elif action == 'restrict':
        valid = not after['disabled'] and after['roles'] == [TELEMETRY_ROLE]
    elif action == 'quarantine':
        valid = after['disabled'] and after['roles'] == [TELEMETRY_ROLE]
    else:
        valid = True
    if not valid:
        raise RuntimeError('Post-command policy metadata mismatch')
    session.emit('admin_complete', action=action, result='PASS',
                 note='Control acknowledgement is not data-plane enforcement proof')


def probe(session, state):
    if state == 'quarantine':
        try:
            session.connect()
        except RuntimeError:
            if session.connack == 135:
                session.emit('reconnection_denied', identity=DEVICE, reason_code=135,
                             result='PASS')
                return
            raise
        raise RuntimeError('Quarantined identity unexpectedly connected')
    session.connect()
    session.emit('authenticated', identity=DEVICE, reason_code=session.connack)
    if state == 'live':
        disconnected = []

        def on_disconnect(client, userdata, flags, reason, properties):
            session.connected = False
            disconnected.append(reason.value)
            session.emit('active_session_disconnected', identity=DEVICE,
                         reason_code=reason.value,
                         server_disconnect_packet=flags.is_disconnect_packet_from_server)

        session.client.on_disconnect = on_disconnect
        session.emit('live_ready', identity=DEVICE, deadline_seconds=60)
        deadline = time.monotonic() + 60
        while not disconnected and time.monotonic() < deadline:
            if session.stop.is_set():
                raise InterruptedError('Shutdown requested')
            session.client.loop(timeout=0.2)
        if not disconnected:
            raise TimeoutError('No active-session disconnect observed within 60 seconds')
        session.emit('live_termination_observed', result='PASS')
        return
    operation = dict(run_id=session.run_id, phase=state, device_id='device01',
                     sequence=1, timestamp=utc(), operation='cycle_complete')
    session.publish(OPERATION_TOPIC, operation, (135,) if state == 'restrict' else (0, 16))
    session.publish('azta/devices/device02/telemetry', operation, (135,))
    session.subscribe('azta/devices/#', 135)
    for sequence in range(1, 6):
        payload = dict(run_id=session.run_id, phase=state, device_id='device01',
                       sequence=sequence, timestamp=utc(), sample=40 + sequence)
        session.publish(TOPIC, payload, (0,))
    session.emit('probe_complete', result='PASS', sequences=[1, 2, 3, 4, 5])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['admin', 'probe'])
    parser.add_argument('action', choices=['inspect', 'prepare', 'restrict', 'quarantine',
                                         'restore', 'full', 'restored', 'live', 'post_restart'])
    parser.add_argument('--run-id', required=True)
    args = parser.parse_args()
    admin_actions = {'inspect', 'prepare', 'restrict', 'quarantine', 'restore'}
    probe_actions = {'full', 'restrict', 'quarantine', 'restored', 'live', 'post_restart'}
    if args.action not in (admin_actions if args.mode == 'admin' else probe_actions):
        parser.error('Action does not apply to selected mode')
    session = None
    try:
        session = Probe('admin' if args.mode == 'admin' else DEVICE,
                        args.run_id, args.action)
        if args.mode == 'admin':
            administer(session, args.action)
        else:
            probe(session, args.action)
        return 0
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as exc:
        # Do not echo arbitrary response objects or credential-bearing exceptions.
        log('gate4_error', run_id=args.run_id, phase=args.action,
            error_type=type(exc).__name__, message='Gate 4 check failed; inspect safe events')
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == '__main__':
    raise SystemExit(main())
