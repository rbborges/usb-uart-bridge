# usb-uart-bridge

Zephyr USB-CDC to UART bridge for a WeAct BlackPill (STM32F411CE), built with
PlatformIO. It is a generic low-latency replacement for an FTDI cable: the host
sets the line coding, the UART side runs on DMA, and both directions are ring
buffered with backpressure. See the comments at the top of `src/main.c` for the
decisions that are load bearing.

```
pio run                 # build
pio run -t upload       # flash over J-Link
JLinkRTTClient          # logs; the CDC port carries data only
```

## Host tools

Both live in `tools/` and need only Python plus `pyserial`.

### Round-trip latency (`latency_test.py`)

Jumper the UART TX to RX (PB6 to PB7 on this board) so everything written comes
straight back, then:

```
python tools\latency_test.py --port COM7
python tools\latency_test.py --port COM7 --sweep            # 1..256 B payloads
python tools\latency_test.py --port COM7 --stream 1048576   # bulk integrity
```

Run the identical command against an FTDI adapter with its latency timer set to
1 ms. That adapter is the acceptance bar, and running the same script against
both is what turns "the FTDI works and this does not" into a number.

### USB tracing at the usbser boundary (`usb_trace.py`)

The firmware measures its own forwarding latency (tens of microseconds, over
RTT). When the application above the bridge sees milliseconds, the missing
evidence is on the Windows side, between `usbser.sys` and the USB stack. A
USBPcap trace records exactly that boundary, and the tool splits every stall
into the side it happened on:

* **dev turnaround** -- host OUT submitted to device IN completed. Covers the
  bridge, the UART, and whatever answers on the wire.
* **app turnaround** -- device IN completed to the next host OUT submitted.
  Covers `usbser.sys`, pyserial, and the application. The firmware cannot
  influence this number at all.

It also reports how long each read URB had been armed before it completed. A
long dwell means the read pipeline was awake and took the data the instant it
appeared; a near-zero dwell means the data was already buffered and was waiting
for somebody to ask for it.

Requires [USBPcap](https://desowin.org/usbpcap/) and Wireshark's `tshark`; both
are found automatically under Program Files.

```
python tools\usb_trace.py --list
```

Match the bridge's COM port to a `[number]` in the tree, note which root hub it
sits under, then **from an elevated shell** (USBPcap is a kernel driver):

```
python tools\usb_trace.py --capture trace.pcap --iface \\.\USBPcap2 --seconds 60
```

Start the failing run while that is recording. Then analysis, which needs no
privileges:

```
python tools\usb_trace.py --analyze trace.pcap --hex
python tools\usb_trace.py --analyze trace.pcap --timeline --hex --gap-ms 2
```
