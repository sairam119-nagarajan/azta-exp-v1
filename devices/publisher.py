'''Publish five reproducible samples; timestamps reflect the actual UTC send time.'''
from datetime import datetime, timezone
import json
import os

from devices.mqtt_runtime import Session, TOPIC, log
import paho.mqtt.client as mqtt


def main():
    session = None
    try:
        session = Session('azta-device-01')
        acknowledgements = {}

        def published(client, userdata, mid, reason, properties):
            acknowledgements[mid] = reason.value

        session.client.on_publish = published
        session.connect()
        topic = os.getenv('MQTT_TOPIC', TOPIC)
        for sequence in range(1, 6):
            payload = dict(device_id='device01', sequence=sequence,
                           timestamp=datetime.now(timezone.utc).isoformat(),
                           sample=40 + sequence)
            info = session.client.publish(topic, json.dumps(payload), qos=1, retain=False)
            if info.rc != mqtt.MQTT_ERR_SUCCESS:
                raise RuntimeError(f'Publish enqueue failed: {info.rc}')
            log('publish_sent', topic=topic, qos=1, **payload)
            session.until(lambda: info.mid in acknowledgements, 5)
            reason = acknowledgements.pop(info.mid)
            log('puback', topic=topic, qos=1, reason_code=reason, **payload)
            if reason >= 128:
                raise RuntimeError(f'Broker denied publish: PUBACK {reason}')
            if sequence < 5 and session.stop.wait(2):
                raise InterruptedError('Shutdown requested')
        log('device_complete', sequences=[1, 2, 3, 4, 5])
        return 0
    except InterruptedError:
        log('interrupted')
        return 130
    except (OSError, ValueError, KeyError, RuntimeError, TimeoutError) as exc:
        log('error', message=str(exc))
        return 1
    finally:
        if session is not None:
            session.close()


if __name__ == '__main__':
    raise SystemExit(main())
