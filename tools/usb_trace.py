#!/usr/bin/env python3
"""Capture and analyse USB traffic at the Windows usbser.sys boundary.

Why this exists: the bridge reports 25-48 us of internal forwarding latency,
yet the application above it sees ~20 ms holes. A USBPcap trace records URB
submissions and completions between usbser.sys and the USB stack, which is the
last uninstrumented hop. Every millisecond of a stall lands visibly on one side
of that boundary:

  * "dev turnaround"  (host OUT submitted -> device IN completed) covers the
    bridge, the UART, and whatever is on the far end of the wire.
  * "app turnaround"  (device IN completed -> next host OUT submitted) covers
    usbser.sys, the serial API, Python, and the application. The bridge cannot
    influence this number at all.

A 20 ms hole in the second column exonerates the firmware; one in the first
column does not.

Usage (capture must run from an elevated shell -- USBPcap is a kernel driver):

    python tools\\usb_trace.py --list
    python tools\\usb_trace.py --capture trace.pcap --iface \\\\.\\USBPcap2 --seconds 60
    python tools\\usb_trace.py --analyze trace.pcap
    python tools\\usb_trace.py --analyze trace.pcap --timeline --hex --gap-ms 5

Analysis needs tshark (Wireshark); capture needs USBPcapCMD. Both are found
automatically under Program Files, or pointed at with --tshark / --usbpcapcmd.
"""

import argparse
import ctypes
import os
import re
import shutil
import signal
import subprocess
import sys

TSHARK_CANDIDATES = [
    r"C:\Program Files\Wireshark\tshark.exe",
    r"C:\Program Files (x86)\Wireshark\tshark.exe",
]
USBPCAPCMD_CANDIDATES = [
    r"C:\Program Files\USBPcap\USBPcapCMD.exe",
    r"C:\Program Files (x86)\USBPcap\USBPcapCMD.exe",
]

# USBPCAP_TRANSFER_TYPE
TRANSFER_NAMES = {0: "isoc", 1: "intr", 2: "ctrl", 3: "bulk", 0xFE: "irp-info"}


def find_tool(explicit, candidates, name):
    if explicit:
        if not os.path.isfile(explicit):
            sys.exit("%s not found at %s" % (name, explicit))
        return explicit
    found = shutil.which(name)
    if found:
        return found
    for c in candidates:
        if os.path.isfile(c):
            return c
    sys.exit("could not find %s; pass its path explicitly" % name)


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ---------------------------------------------------------------- listing


def list_interfaces(usbpcapcmd):
    """Print the USBPcap root hubs, the devices behind each, and the COM ports.

    The device number in [brackets] is what --devices takes, and it is also the
    usb.device_address that shows up in the capture.
    """
    out = subprocess.run([usbpcapcmd, "--extcap-interfaces"],
                         capture_output=True, text=True).stdout
    ifaces = re.findall(r"\{value=([^}]+)\}", out)
    if not ifaces:
        sys.exit("USBPcapCMD listed no interfaces")

    for iface in ifaces:
        print("\n%s" % iface)
        cfg = subprocess.run(
            [usbpcapcmd, "--extcap-interface", iface, "--extcap-config"],
            capture_output=True, text=True).stdout
        for line in cfg.splitlines():
            m = re.match(r"value \{arg=99\}\{value=([^}]+)\}\{display=([^}]*)\}"
                         r"(?:\{enabled=\w+\})?(?:\{parent=([^}]+)\})?", line)
            if not m:
                continue
            value, display, parent = m.groups()
            depth = value.count("_")
            print("  %s%-6s %s" % ("  " * depth, value, display))

    print("\nserial ports:")
    try:
        from serial.tools import list_ports
    except ImportError:
        print("  (pyserial not installed -- pip install pyserial)")
        return
    for p in list_ports.comports():
        print("  %-6s %-40s %s" % (p.device, p.description, p.hwid))
    print("\nMatch the bridge's COM port to a [device] number above, then capture"
          "\nthat root hub. Capturing the whole hub is fine; --analyze picks the"
          "\nbusiest device unless you pass --device.")


# ---------------------------------------------------------------- capture


def capture(usbpcapcmd, path, iface, seconds, devices, snaplen, bufferlen):
    if not is_admin():
        sys.exit("USBPcap capture needs an elevated shell.\n"
                 "Open a new terminal with 'Run as administrator' and re-run this"
                 " command there.")

    cmd = [usbpcapcmd, "-d", iface, "-o", path,
           "-s", str(snaplen), "-b", str(bufferlen)]
    if devices:
        cmd += ["--devices", devices]
    else:
        cmd += ["-A"]

    print("capturing to %s" % path)
    print("  %s" % " ".join(cmd))
    if seconds:
        print("  running for %g s -- start the failing run NOW" % seconds)
    else:
        print("  running until Ctrl-C")

    proc = subprocess.Popen(cmd, creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
    try:
        proc.wait(timeout=seconds if seconds else None)
    except subprocess.TimeoutExpired:
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    except KeyboardInterrupt:
        proc.send_signal(signal.CTRL_BREAK_EVENT)
        proc.wait(timeout=5)

    size = os.path.getsize(path) if os.path.exists(path) else 0
    print("wrote %s (%d bytes)" % (path, size))
    if size <= 24:
        print("WARNING: capture is empty. Wrong root hub, or the device was not"
              " active.")


# ---------------------------------------------------------------- analysis


FIELDS = [
    "frame.number",
    "frame.time_epoch",
    "usb.device_address",
    "usb.endpoint_address",
    "usb.transfer_type",
    "usb.irp_info.direction",   # 0 = FDO->PDO (submit), 1 = PDO->FDO (complete)
    "usb.irp_id",
    "usb.data_len",
    "usb.capdata",
    "data.data",
]


class Event(object):
    __slots__ = ("frame", "t", "dev", "ep", "xfer", "complete", "irp",
                 "length", "payload")

    @property
    def is_in(self):
        return bool(self.ep & 0x80)


def read_events(tshark, path, device=None):
    cmd = [tshark, "-r", path, "-T", "fields", "-E", "separator=|",
           "-E", "occurrence=f"]
    for f in FIELDS:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.exit("tshark failed:\n%s" % proc.stderr.strip())

    events = []
    for line in proc.stdout.splitlines():
        cols = line.split("|")
        if len(cols) < len(FIELDS):
            continue
        (frame, t, dev, ep, xfer, irpdir, irp, dlen, capdata, datadata) = cols[:10]
        if not dev or not ep:
            continue
        e = Event()
        try:
            e.frame = int(frame)
            e.t = float(t)
            e.dev = int(dev)
            e.ep = int(ep, 0)
            e.xfer = int(xfer, 0) if xfer else -1
        except ValueError:
            continue
        # tshark renders this as 0x00 / 0x01, hence the base-0 parse.
        e.complete = bool(int(irpdir, 0)) if irpdir else False
        e.irp = irp
        hexdata = (capdata or datadata or "").replace(":", "")
        e.payload = bytes.fromhex(hexdata) if hexdata else b""
        try:
            e.length = int(dlen)
        except ValueError:
            e.length = len(e.payload)
        if device is None or e.dev == device:
            events.append(e)
    events.sort(key=lambda x: x.t)
    return events


def pick_device(events):
    """Busiest device by data bytes -- in practice the bridge under test."""
    totals = {}
    for e in events:
        if e.xfer in (1, 3) and e.length:
            totals[e.dev] = totals.get(e.dev, 0) + e.length
    if not totals:
        return None
    return max(totals, key=totals.get)


def data_events(events):
    """Timeline of moments data actually crossed the usbser boundary.

    An OUT carries its payload on the submit (host handed it down); an IN
    carries it on the completion (the stack handed it up). Anything else is
    bookkeeping.
    """
    out = []
    for e in events:
        if e.xfer not in (1, 3) or not e.length:
            continue
        if e.is_in and e.complete:
            out.append(e)
        elif not e.is_in and not e.complete:
            out.append(e)
    return out


def urb_dwell(events):
    """submit -> complete time per IN URB, keyed by the completion frame.

    A long dwell means the read URB sat armed and empty, so the instant the
    device produced data the stack took it: the host read pipeline was awake.
    A near-zero dwell means data was already buffered when the URB arrived --
    the read pipeline was the thing that was late.
    """
    pending = {}
    dwell = {}
    outstanding = {}
    n = 0
    for e in events:
        if not e.is_in or e.xfer not in (1, 3):
            continue
        if not e.complete:
            pending[e.irp] = e.t
            n += 1
        else:
            t0 = pending.pop(e.irp, None)
            if t0 is not None:
                dwell[e.frame] = e.t - t0
                n -= 1
            outstanding[e.frame] = max(n, 0)
    return dwell, outstanding


def runs(evts):
    """Collapse consecutive same-direction events into one run each."""
    grouped = []
    for e in evts:
        if grouped and grouped[-1][0] == e.is_in:
            grouped[-1][1].append(e)
        else:
            grouped.append((e.is_in, [e]))
    return grouped


def pct(vals, p):
    if not vals:
        return float("nan")
    s = sorted(vals)
    return s[min(int(len(s) * p), len(s) - 1)]


def stat_line(label, vals):
    if not vals:
        return "  %-38s n=0" % label
    return ("  %-38s n=%-5d p50 %7.3f ms  p90 %7.3f ms  p99 %7.3f ms  max %8.3f ms"
            % (label, len(vals), pct(vals, .50), pct(vals, .90),
               pct(vals, .99), max(vals)))


def hexdump(payload, limit=24):
    h = payload[:limit].hex(" ")
    return h + (" ..." if len(payload) > limit else "")


def analyze(tshark, path, device, gap_ms, show_timeline, show_hex, top):
    events = read_events(tshark, path)
    if not events:
        sys.exit("no USB events in %s" % path)

    if device is None:
        device = pick_device(events)
        if device is None:
            sys.exit("no bulk or interrupt data in the capture")
    events = [e for e in events if e.dev == device]
    evts = data_events(events)
    if not evts:
        sys.exit("device %d has no data-bearing transfers" % device)

    eps_in = sorted({e.ep for e in evts if e.is_in})
    eps_out = sorted({e.ep for e in evts if not e.is_in})
    span = evts[-1].t - evts[0].t
    bytes_in = sum(e.length for e in evts if e.is_in)
    bytes_out = sum(e.length for e in evts if not e.is_in)
    xfer = TRANSFER_NAMES.get(evts[0].xfer, "?")

    print("\n=== device %d  (%s, IN %s, OUT %s) ===" %
          (device, xfer,
           " ".join("0x%02x" % x for x in eps_in) or "-",
           " ".join("0x%02x" % x for x in eps_out) or "-"))
    print("  %d data transfers over %.3f s" % (len(evts), span))
    print("  device -> host %d B   host -> device %d B" % (bytes_in, bytes_out))

    dwell, outstanding = urb_dwell(events)

    grouped = runs(evts)
    app_turn, dev_turn, records = [], [], []
    for i in range(1, len(grouped)):
        prev_dir, prev = grouped[i - 1]
        cur_dir, cur = grouped[i]
        dt_ms = (cur[0].t - prev[-1].t) * 1e3
        # prev was IN, cur is OUT: everything above usbser had the data and
        # took this long to answer. prev OUT -> cur IN: the wire side.
        if prev_dir and not cur_dir:
            app_turn.append(dt_ms)
            records.append(("app", dt_ms, prev[-1], cur[0]))
        elif not prev_dir and cur_dir:
            dev_turn.append(dt_ms)
            records.append(("dev", dt_ms, prev[-1], cur[0]))

    print()
    print(stat_line("app turnaround (IN -> next OUT)", app_turn))
    print(stat_line("dev turnaround (OUT -> next IN)", dev_turn))
    if dwell:
        dw = [v * 1e3 for v in dwell.values()]
        print(stat_line("IN URB dwell (submit -> complete)", dw))
        starved = sum(1 for v in dw if v < 0.05)
        print("  %d of %d IN completions had a dwell under 50 us -- data was"
              " already waiting when the read was posted" % (starved, len(dw)))
        never = sum(1 for k, v in outstanding.items() if v == 0)
        if never:
            print("  %d IN completions left zero read URBs outstanding" % never)

    slow = [r for r in records if r[1] >= gap_ms]
    slow.sort(key=lambda r: -r[1])
    print("\noutliers over %.1f ms: %d" % (gap_ms, len(slow)))
    t0 = evts[0].t
    for kind, dt_ms, prev, cur in slow[:top]:
        side = ("above usbser (host software)" if kind == "app"
                else "below usbser (bridge / UART / far end)")
        print("  t=%9.4f s  %s %8.3f ms  %s" % (prev.t - t0, kind, dt_ms, side))
        print("      from frame %d %s %d B%s" %
              (prev.frame, "IN " if prev.is_in else "OUT", prev.length,
               "  " + hexdump(prev.payload) if show_hex else ""))
        print("      to   frame %d %s %d B%s" %
              (cur.frame, "IN " if cur.is_in else "OUT", cur.length,
               "  " + hexdump(cur.payload) if show_hex else ""))
        if kind == "app" and prev.frame in dwell:
            print("      the IN URB had been armed %.3f ms before it completed"
                  % (dwell[prev.frame] * 1e3))

    if app_turn and dev_turn:
        print("\nverdict: worst app turnaround %.3f ms, worst dev turnaround"
              " %.3f ms." % (max(app_turn), max(dev_turn)))
        if max(app_turn) > 3 * max(dev_turn):
            print("  The long stalls are above usbser.sys. The bridge delivered"
                  "\n  its data and then waited on the host software.")
        elif max(dev_turn) > 3 * max(app_turn):
            print("  The long stalls are below usbser.sys -- the bridge, the"
                  "\n  UART, or whatever is answering on the wire.")

    if show_timeline:
        print("\ntimeline (t=0 at first data transfer):")
        prev_t = evts[0].t
        for e in evts:
            print("  %9.4f s  +%8.3f ms  f%-7d %s %4d B  %s" %
                  (e.t - t0, (e.t - prev_t) * 1e3, e.frame,
                   "IN " if e.is_in else "OUT", e.length,
                   hexdump(e.payload) if show_hex else ""))
            prev_t = e.t


def main():
    ap = argparse.ArgumentParser(
        description="USBPcap capture and usbser-boundary latency analysis.")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--list", action="store_true",
                      help="show USBPcap root hubs, their devices, and COM ports")
    mode.add_argument("--capture", metavar="FILE", help="record a capture")
    mode.add_argument("--analyze", metavar="FILE", help="analyse a capture")

    ap.add_argument("--iface", default=None,
                    help=r"USBPcap interface for --capture, e.g. \\.\USBPcap2")
    ap.add_argument("--devices", default=None,
                    help="comma-separated device numbers to capture (default: all)")
    ap.add_argument("--seconds", type=float, default=0,
                    help="capture duration; 0 means until Ctrl-C")
    ap.add_argument("--snaplen", type=int, default=65535)
    ap.add_argument("--bufferlen", type=int, default=1 << 22,
                    help="kernel capture buffer (default 4 MiB)")

    ap.add_argument("--device", type=int, default=None,
                    help="usb.device_address to analyse (default: busiest)")
    ap.add_argument("--gap-ms", type=float, default=5.0,
                    help="report turnarounds at or above this (default 5 ms)")
    ap.add_argument("--top", type=int, default=20,
                    help="how many outliers to print (default 20)")
    ap.add_argument("--timeline", action="store_true", help="print every transfer")
    ap.add_argument("--hex", action="store_true", help="include payload bytes")

    ap.add_argument("--tshark", default=None)
    ap.add_argument("--usbpcapcmd", default=None)
    args = ap.parse_args()

    if args.list:
        list_interfaces(find_tool(args.usbpcapcmd, USBPCAPCMD_CANDIDATES,
                                  "USBPcapCMD.exe"))
    elif args.capture:
        if not args.iface:
            sys.exit("--capture needs --iface; run --list to see the choices")
        capture(find_tool(args.usbpcapcmd, USBPCAPCMD_CANDIDATES, "USBPcapCMD.exe"),
                args.capture, args.iface, args.seconds, args.devices,
                args.snaplen, args.bufferlen)
    else:
        analyze(find_tool(args.tshark, TSHARK_CANDIDATES, "tshark.exe"),
                args.analyze, args.device, args.gap_ms, args.timeline,
                args.hex, args.top)


if __name__ == "__main__":
    main()
