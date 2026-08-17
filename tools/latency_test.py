#!/usr/bin/env python3
"""
Round-trip latency and integrity test for a USB-UART bridge.

Wiring: jumper the bridge's UART TX to its UART RX so everything written comes
straight back. On the BlackPill build that is PB6 -> PB7. No other hardware is
needed; the loop is PC -> USB -> bridge -> UART TX -> wire -> UART RX ->
bridge -> USB -> PC.

Usage:
    python latency_test.py --port COM7
    python latency_test.py --port COM7 --baud 1000000 --size 8 --count 2000
    python latency_test.py --port COM7 --sweep
    python latency_test.py --port COM7 --stream 1048576

What the numbers mean: the measured round trip includes two crossings of the
host USB stack, which on Windows is scheduled in 1 ms frames and is normally
the dominant term. The firmware's own RTT log reports its internal forwarding
latency separately; if that stays in microseconds while these numbers are
larger, the remaining time is the host, not the bridge.
"""

import argparse
import statistics
import sys
import time

try:
    import serial
except ImportError:
    sys.exit("pyserial is required:  pip install pyserial")


def wire_time_us(nbytes, baud, bits_per_byte=10):
    """Time to serialize nbytes in each direction, in microseconds."""
    return 2.0 * nbytes * bits_per_byte / baud * 1e6


def roundtrip(ser, payload):
    """Write payload, read it back, return elapsed seconds (None on timeout)."""
    t0 = time.perf_counter()
    ser.write(payload)
    got = bytearray()
    while len(got) < len(payload):
        chunk = ser.read(len(payload) - len(got))
        if not chunk:
            return None, bytes(got)
        got += chunk
    return time.perf_counter() - t0, bytes(got)


def histogram(samples_us, bins=12, width=48):
    lo, hi = min(samples_us), max(samples_us)
    if hi - lo < 1e-9:
        return ["  all samples at %.1f us" % lo]
    step = (hi - lo) / bins
    counts = [0] * bins
    for s in samples_us:
        i = min(int((s - lo) / step), bins - 1)
        counts[i] += 1
    peak = max(counts) or 1
    out = []
    for i, c in enumerate(counts):
        edge = lo + i * step
        bar = "#" * int(width * c / peak)
        out.append("  %8.1f us | %-*s %d" % (edge, width, bar, c))
    return out


def measure(ser, size, count, warmup, interval, quiet=False):
    """Run `count` round trips of `size` bytes. Returns (latencies_us, errors)."""
    lat = []
    timeouts = 0
    corrupt = 0

    for i in range(warmup + count):
        # Vary the payload so a stale buffer cannot masquerade as a response.
        payload = bytes(((i + j) & 0xFF) for j in range(size))
        ser.reset_input_buffer()

        dt, got = roundtrip(ser, payload)

        if dt is None:
            timeouts += 1
            continue
        if got != payload:
            corrupt += 1
            continue
        if i >= warmup:
            lat.append(dt * 1e6)
        if interval:
            time.sleep(interval)

    if not quiet and (timeouts or corrupt):
        print("  WARNING: %d timeouts, %d corrupted responses" % (timeouts, corrupt))
    return lat, timeouts + corrupt


def pct(sorted_vals, p):
    if not sorted_vals:
        return float("nan")
    k = min(int(len(sorted_vals) * p), len(sorted_vals) - 1)
    return sorted_vals[k]


def report(size, baud, lat, errors, show_hist):
    wire = wire_time_us(size, baud)
    print("\npayload %d B @ %d baud   (wire time both ways: %.1f us)" % (size, baud, wire))
    if not lat:
        print("  no successful round trips (%d errors)" % errors)
        return
    s = sorted(lat)
    print("  samples %d, errors %d" % (len(s), errors))
    print("  min  %9.1f us" % s[0])
    print("  p50  %9.1f us" % pct(s, 0.50))
    print("  p90  %9.1f us" % pct(s, 0.90))
    print("  p99  %9.1f us" % pct(s, 0.99))
    print("  max  %9.1f us" % s[-1])
    print("  jitter (p99 - min) %.1f us" % (pct(s, 0.99) - s[0]))
    print("  overhead beyond wire time (p50): %.1f us" % (pct(s, 0.50) - wire))
    if show_hist:
        print("  distribution:")
        for line in histogram(s):
            print(line)


def stream_test(ser, nbytes, baud, chunk=2048):
    """Push a large block through the loopback and verify nothing is lost.

    The return path is drained by a dedicated thread. The uart->usb direction
    has no way to apply backpressure to an already-transmitting peer, so a
    reader that stalls behind the writer would overflow the bridge and show up
    as data loss that is really the test's own fault. Decoupling the two is
    also how an application on top of a serial port should be written.
    """
    import threading

    print("\nstreaming %d bytes @ %d baud" % (nbytes, baud))
    ser.reset_input_buffer()

    pattern = bytes(range(256))
    got = bytearray()
    done = threading.Event()

    def reader():
        while not done.is_set() or ser.in_waiting:
            r = ser.read(max(1, min(chunk, ser.in_waiting)))
            if r:
                got.extend(r)
            elif done.is_set():
                return

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    sent = 0
    t0 = time.perf_counter()
    while sent < nbytes:
        n = min(chunk, nbytes - sent)
        block = (pattern * (n // 256 + 1))[:n]
        ser.write(block)
        sent += n

    deadline = time.perf_counter() + 5.0
    while len(got) < sent and time.perf_counter() < deadline:
        time.sleep(0.01)
    elapsed = time.perf_counter() - t0
    done.set()
    t.join(timeout=2.0)

    expected = (pattern * (sent // 256 + 1))[:sent]
    ok = bytes(got) == expected

    print("  sent %d B, received %d B in %.3f s" % (sent, len(got), elapsed))
    print("  throughput %.1f kB/s (line rate %.1f kB/s)"
          % (sent / elapsed / 1000.0, baud / 10.0 / 1000.0))
    if ok:
        print("  integrity OK")
    elif len(got) < sent:
        print("  LOST %d bytes" % (sent - len(got)))
    else:
        first = next((i for i in range(len(got)) if got[i] != expected[i]), None)
        print("  CORRUPTED at offset %s" % first)
    return ok


def main():
    ap = argparse.ArgumentParser(
        description="Round-trip latency test for a USB-UART bridge (TX looped to RX).")
    ap.add_argument("--port", required=True, help="serial port, e.g. COM7 or /dev/ttyACM0")
    ap.add_argument("--baud", type=int, default=1000000, help="baud rate (default 1000000)")
    ap.add_argument("--size", type=int, default=8, help="payload bytes (default 8)")
    ap.add_argument("--count", type=int, default=1000, help="measured round trips (default 1000)")
    ap.add_argument("--warmup", type=int, default=50, help="discarded round trips (default 50)")
    ap.add_argument("--interval", type=float, default=0.0,
                    help="seconds to idle between round trips (default 0)")
    ap.add_argument("--timeout", type=float, default=0.5, help="read timeout (default 0.5 s)")
    ap.add_argument("--sweep", action="store_true", help="test a range of payload sizes")
    ap.add_argument("--stream", type=int, metavar="BYTES", default=0,
                    help="also run a bulk integrity/throughput test")
    ap.add_argument("--no-histogram", action="store_true")
    args = ap.parse_args()

    try:
        ser = serial.Serial(args.port, args.baud, timeout=args.timeout, write_timeout=2.0)
    except serial.SerialException as e:
        sys.exit("could not open %s: %s" % (args.port, e))

    with ser:
        time.sleep(0.2)          # let the port settle after open
        ser.reset_input_buffer()

        probe, _ = roundtrip(ser, b"\xA5")
        if probe is None:
            sys.exit("no loopback: nothing came back. Is UART TX jumpered to RX?")

        print("port %s open, loopback confirmed" % args.port)

        sizes = [1, 8, 32, 64, 128, 256] if args.sweep else [args.size]
        for size in sizes:
            lat, errors = measure(ser, size, args.count, args.warmup, args.interval)
            report(size, args.baud, lat, errors, not args.no_histogram and not args.sweep)

        if args.stream:
            stream_test(ser, args.stream, args.baud)


if __name__ == "__main__":
    main()
