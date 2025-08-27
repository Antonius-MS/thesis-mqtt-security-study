#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import paho.mqtt.client as mqtt
import time
from paho.mqtt.properties import Properties
from paho.mqtt.packettypes import PacketTypes
from paho.mqtt.client import CallbackAPIVersion

BROKER = "localhost"
PORT = 1883
TOPIC = "test/duplicate"
MSG_COUNT = 50
PUBLISH_DELAY = 0.05
WAIT_TIME = 8

received = []

def on_connect(client, userdata, flags, rc, props=None):
    print(f"[{time.strftime('%H:%M:%S')}] Connected")
    client.subscribe(TOPIC, qos=userdata['qos'])

def on_message(client, userdata, msg):
    received.append(msg.payload.decode())

def clear_all_sessions():
    """Thoroughly clear all client sessions"""
    for client_id in ["test-sub", "test-pub"]:
        c = mqtt.Client(
            client_id=client_id,
            protocol=mqtt.MQTTv5,
            callback_api_version=CallbackAPIVersion.VERSION2
        )
        props = Properties(PacketTypes.CONNECT)
        props.SessionExpiryInterval = 0  # Expire immediately
        try:
            c.connect(BROKER, PORT, clean_start=1, properties=props)
            c.loop_start()
            time.sleep(0.3)
            c.loop_stop()
            c.disconnect()
        except:
            pass  # Ignore connection errors during cleanup
    time.sleep(0.5)

def run_single_test(qos, run_number):
    """Run a single test with completely fresh clients"""
    global received
    received = []

    # Use unique client IDs for each run to avoid any session conflicts
    sub_id = f"test-sub-{run_number}"
    pub_id = f"test-pub-{run_number}"

    print(f"[{time.strftime('%H:%M:%S')}]  Run {run_number}: QoS {qos}")

    # Subscriber with clean session (no persistence to avoid interference)
    sub = mqtt.Client(
        client_id=sub_id,
        protocol=mqtt.MQTTv5,
        callback_api_version=CallbackAPIVersion.VERSION2,
        userdata={'qos': qos}
    )
    sub.on_connect = on_connect
    sub.on_message = on_message

    # Connect with clean session
    sub.connect(BROKER, PORT, clean_start=1)
    sub.loop_start()
    time.sleep(1)  # Ensure connection is stable

    # Publisher with clean session
    pub = mqtt.Client(
        client_id=pub_id,
        protocol=mqtt.MQTTv5,
        callback_api_version=CallbackAPIVersion.VERSION2
    )
    pub.connect(BROKER, PORT, clean_start=1)
    pub.loop_start()
    time.sleep(0.5)

    # Publish messages
    start_time = time.time()
    for i in range(1, MSG_COUNT + 1):
        payload = f"R{run_number:02d}M{i:03d}"  # Run02Msg001 format
        pub.publish(TOPIC, payload, qos=qos)
        time.sleep(PUBLISH_DELAY)

    publish_duration = time.time() - start_time
    print(f"[{time.strftime('%H:%M:%S')}]  Published {MSG_COUNT} messages in {publish_duration:.1f}s")

    # Wait for all messages (including duplicates from retransmissions)
    print(f"[{time.strftime('%H:%M:%S')}]  Collecting messages for {WAIT_TIME}s...")
    time.sleep(WAIT_TIME)

    # Cleanup
    pub.loop_stop()
    pub.disconnect()
    sub.loop_stop()
    sub.disconnect()

    # Analyze results
    total = len(received)
    unique_msgs = set(received)
    unique_count = len(unique_msgs)
    duplicates = total - unique_count

    # Check for missing messages
    expected = {f"R{run_number:02d}M{i:03d}" for i in range(1, MSG_COUNT + 1)}
    missing = expected - unique_msgs
    missing_count = len(missing)

    print(f"[{time.strftime('%H:%M:%S')}]  Results:")
    print(f"   Published: {MSG_COUNT}")
    print(f"   Received: {total}")
    print(f"   Unique: {unique_count}")
    print(f"   Missing: {missing_count}")
    print(f"   Duplicates: {duplicates}")

    if duplicates > 0:
        # Show duplicate statistics
        from collections import Counter
        counts = Counter(received)
        duplicate_msgs = {msg: count for msg, count in counts.items() if count > 1}
        print(f"   🔄 Duplicate messages: {len(duplicate_msgs)}")

    return {
        'run': run_number,
        'qos': qos,
        'published': MSG_COUNT,
        'received': total,
        'unique': unique_count,
        'missing': missing_count,
        'duplicates': duplicates,
        'duplicate_rate': duplicates / MSG_COUNT if MSG_COUNT > 0 else 0
    }

def main():
    print(" MQTT Duplicate Message Test with tc Network Loss")
    print("=" * 60)
    print(f"  Make sure tc packet loss is active:")
    print(f"   sudo tc qdisc add dev lo root netem loss 30%")
    print("=" * 60)

    all_results = []

    # Test each QoS with 5 runs
    for qos in [1, 2]:
        print(f"\n Testing QoS {qos} - 5 runs")
        print("-" * 40)

        qos_results = []

        for run in range(1, 6):
            # Clear sessions before each run for maximum reliability
            clear_all_sessions()

            # Run the test
            result = run_single_test(qos, run)
            qos_results.append(result)
            all_results.append(result)

            # Short pause between runs
            time.sleep(1)

        # QoS Summary
        total_published = sum(r['published'] for r in qos_results)
        total_received = sum(r['received'] for r in qos_results)
        total_duplicates = sum(r['duplicates'] for r in qos_results)
        avg_duplicate_rate = sum(r['duplicate_rate'] for r in qos_results) / len(qos_results)

        print(f"\n QoS {qos} Summary (5 runs):")
        print(f"   Total published: {total_published}")
        print(f"   Total received: {total_received}")
        print(f"   Total duplicates: {total_duplicates}")
        print(f"   Average duplicate rate: {avg_duplicate_rate:.2%}")

        # Show per-run results
        print(f"   Per-run breakdown:")
        for r in qos_results:
            print(f"     Run {r['run']}: {r['duplicates']}/{r['published']} duplicates ({r['duplicate_rate']:.1%})")

    # Final Summary
    print("\n" + "=" * 60)
    print(" FINAL SUMMARY")
    print("=" * 60)

    for qos in [1, 2]:
        qos_runs = [r for r in all_results if r['qos'] == qos]
        avg_dups = sum(r['duplicates'] for r in qos_runs) / len(qos_runs)
        max_dups = max(r['duplicates'] for r in qos_runs)
        min_dups = min(r['duplicates'] for r in qos_runs)

        print(f"QoS {qos}: avg={avg_dups:.1f}, min={min_dups}, max={max_dups} duplicates per run")

    print(f"\n Expected with tc packet loss:")
    print(f"   QoS 1: Should show duplicates (at-least-once delivery)")
    print(f"   QoS 2: Should show fewer/no duplicates (exactly-once delivery)")

    print(f"\n To remove packet loss:")
    print(f"   sudo tc qdisc del dev lo root")

if __name__ == "__main__":
    main()
