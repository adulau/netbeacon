#!/usr/bin/env python3
"""Collect netbeacon UDP packets from a live interface or pcap input."""

from __future__ import annotations

import re
import socket
import sys
import time
from dataclasses import dataclass
from optparse import OptionParser

NETBEACON_PATTERN = re.compile(r"^nb")


@dataclass
class CaptureStats:
    """Track packet capture and netbeacon analysis counters."""

    received: int = 0
    analyzed: int = 0
    matched: int = 0
    decode_errors: int = 0


def decode_payload(payload: bytes) -> str:
    """Decode a UDP payload to text if possible."""
    return payload.decode("ascii", errors="replace")


def _emit_stats(stats: CaptureStats, started_at: float, label: str = "stats") -> None:
    elapsed = max(time.time() - started_at, 0.000001)
    rate = stats.received / elapsed
    sys.stderr.write(
        f"\n[{label}] received={stats.received} analyzed={stats.analyzed} matched={stats.matched} "
        f"decode_errors={stats.decode_errors} rate={rate:.2f} pkt/s"
    )


def main() -> int:
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-i", "--interface", dest="interface", help="live capture on interface (default: lo)")
    parser.add_option("-r", "--read", dest="filedump", help="read pcap file")
    parser.add_option("-e", "--extended", dest="extended", action="store_true", help="enable extended format including pcap timestamp")
    parser.add_option("-m", "--monitor", dest="monitor", action="store_true", help="emit periodic live statistics to stderr")
    parser.add_option("--monitor-interval", dest="monitor_interval", type=int, default=5, help="seconds between live monitor updates (default: 5)")
    parser.add_option("--debug", dest="debug", action="store_true", help="light debug output with capture summary")
    parser.add_option("--debug-full", dest="debug_full", action="store_true", help="full debug output including packet-level details")
    options, _args = parser.parse_args()

    interface = options.interface or "lo"
    if options.filedump:
        interface = options.filedump

    try:
        import dpkt
        import pcap
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "nb_collect.py requires the dpkt and pcap packages. Install them with `python3 -m pip install dpkt pcap`."
        ) from exc

    pc = pcap.pcap(interface)
    pc.setfilter("port 12345 and udp")

    decode_map = {
        pcap.DLT_LOOP: dpkt.loopback.Loopback,
        pcap.DLT_NULL: dpkt.loopback.Loopback,
        pcap.DLT_EN10MB: dpkt.ethernet.Ethernet,
    }
    decoder = decode_map.get(pc.datalink())
    if decoder is None:
        raise RuntimeError(f"unsupported datalink type: {pc.datalink()}")

    stats = CaptureStats()
    started_at = time.time()
    monitor_interval = max(int(options.monitor_interval or 1), 1)
    next_emit = started_at + monitor_interval
    debug = bool(options.debug or options.debug_full)

    try:
        if debug:
            sys.stderr.write(f"listening on {pc.name}: {pc.filter}\n")

        for ts, pkt in pc:
            stats.received += 1
            try:
                frame = decoder(pkt)
                ip = frame.data
                udp = ip.data
                payload = decode_payload(udp.data)
                source = socket.inet_ntoa(ip.src)
            except Exception as exc:  # pragma: no cover - dependent on capture format/runtime packets
                stats.decode_errors += 1
                if options.debug_full:
                    sys.stderr.write(f"[debug-full] decode failure at packet {stats.received}: {exc}\n")
                continue

            stats.analyzed += 1
            matched = bool(NETBEACON_PATTERN.search(payload))
            if matched:
                stats.matched += 1
                if options.extended:
                    print(f"{ts}|{source}|{payload}")
                else:
                    print(payload)

            if options.debug_full:
                sys.stderr.write(
                    f"[debug-full] packet={stats.received} source={source} bytes={len(payload)} matched={matched}\n"
                )

            if options.monitor and time.time() >= next_emit:
                _emit_stats(stats, started_at, label="monitor")
                next_emit = time.time() + monitor_interval

    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted by user")
    finally:
        if debug or options.monitor:
            _emit_stats(stats, started_at, label="final")
        try:
            nrecv, ndrop, _nifdrop = pc.stats()
            sys.stderr.write(f"\nlibpcap received={nrecv} dropped={ndrop}\n")
        except Exception:
            if debug:
                sys.stderr.write("\nlibpcap stats unavailable\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
