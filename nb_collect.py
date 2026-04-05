#!/usr/bin/env python3
"""Collect netbeacon UDP packets from a live interface or pcap input."""

from __future__ import annotations

import re
import socket
import sys
import time
from dataclasses import dataclass
from optparse import OptionParser
from typing import Dict, Iterator, Tuple

NETBEACON_PATTERN = re.compile(r"^nb")


@dataclass
class CaptureStats:
    """Track packet capture and netbeacon analysis counters."""

    received: int = 0
    analyzed: int = 0
    matched: int = 0
    decode_errors: int = 0
    netbeacon_parsed: int = 0
    lost_packets: int = 0
    reordered_packets: int = 0
    duplicate_packets: int = 0


def decode_payload(payload: bytes) -> str:
    """Decode a UDP payload to text if possible."""
    return payload.decode("ascii", errors="replace")


def _emit_stats(stats: CaptureStats, started_at: float, label: str = "stats") -> None:
    elapsed = max(time.time() - started_at, 0.000001)
    rate = stats.received / elapsed
    sys.stderr.write(
        f"\n[{label}] received={stats.received} analyzed={stats.analyzed} matched={stats.matched} "
        f"decode_errors={stats.decode_errors} parsed={stats.netbeacon_parsed} lost={stats.lost_packets} "
        f"reordered={stats.reordered_packets} duplicates={stats.duplicate_packets} rate={rate:.2f} pkt/s"
    )


def _extract_sequence(payload: str) -> int | None:
    """Extract the netbeacon sequence number from payload text."""
    parts = payload.split(";")
    if len(parts) < 4 or parts[0] != "nb":
        return None
    try:
        return int(parts[2])
    except ValueError:
        return None


def _load_capture_backend():
    """Load a packet-capture backend.

    Prefers the classic ``pcap`` module and falls back to ``python-libpcap``.
    Returns a tuple of ``(backend_name, factory)`` where factory yields
    ``(packet_iterable, datalink_type, capture_name, capture_filter, stats_fn)``.
    """
    try:
        import pcap as pcap_module
    except ModuleNotFoundError:
        pcap_module = None

    if pcap_module is not None:
        import dpkt

        def _pcap_factory(source: str, is_file: bool, capture_filter: str):
            pc = pcap_module.pcap(source)
            pc.setfilter(capture_filter)
            decode_map = {
                pcap_module.DLT_LOOP: dpkt.loopback.Loopback,
                pcap_module.DLT_NULL: dpkt.loopback.Loopback,
                pcap_module.DLT_EN10MB: dpkt.ethernet.Ethernet,
            }
            decoder = decode_map.get(pc.datalink())
            if decoder is None:
                raise RuntimeError(f"unsupported datalink type: {pc.datalink()}")
            return pc, pc.datalink(), pc.name, pc.filter, pc.stats

        return "pcap", _pcap_factory

    try:
        from pylibpcap.pcap import rpcap, sniff
    except ModuleNotFoundError as exc:
        raise SystemExit(
            "nb_collect.py requires dpkt and either `pcap` or `python-libpcap` packages. "
            "Install with `python3 -m pip install dpkt pcap` or `python3 -m pip install dpkt python-libpcap`."
        ) from exc

    import dpkt

    def _iter_python_libpcap(source: str, is_file: bool, capture_filter: str) -> Iterator[Tuple[float, bytes]]:
        if is_file:
            for _plen, ts, pkt in rpcap(source, filters=capture_filter):
                yield ts, pkt
        else:
            for _plen, ts, pkt in sniff(source, filters=capture_filter, count=-1, promisc=1):
                yield ts, pkt

    def _python_libpcap_factory(source: str, is_file: bool, capture_filter: str):
        iterable = _iter_python_libpcap(source, is_file, capture_filter)
        return iterable, None, source, capture_filter, None

    return "python-libpcap", _python_libpcap_factory


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

    source = options.filedump or options.interface or "lo"
    is_file = bool(options.filedump)
    capture_filter = "port 12345 and udp"
    backend_name, capture_factory = _load_capture_backend()

    import dpkt

    packet_stream, datalink_type, capture_name, active_filter, stats_fn = capture_factory(source, is_file, capture_filter)
    decode_map = {}
    if datalink_type is not None:
        try:
            import pcap as pcap_module
        except ModuleNotFoundError:
            pcap_module = None
        if pcap_module is not None:
            decode_map = {
                pcap_module.DLT_LOOP: dpkt.loopback.Loopback,
                pcap_module.DLT_NULL: dpkt.loopback.Loopback,
                pcap_module.DLT_EN10MB: dpkt.ethernet.Ethernet,
            }

    stats = CaptureStats()
    last_seen_seq_by_source: Dict[str, int] = {}
    started_at = time.time()
    monitor_interval = max(int(options.monitor_interval or 1), 1)
    next_emit = started_at + monitor_interval
    debug = bool(options.debug or options.debug_full)

    try:
        if debug:
            sys.stderr.write(f"listening on {capture_name}: {active_filter} (backend={backend_name})\n")

        for ts, pkt in packet_stream:
            stats.received += 1
            try:
                if datalink_type is None:
                    decode_error = None
                    ip = None
                    for decoder in (dpkt.loopback.Loopback, dpkt.ethernet.Ethernet):
                        try:
                            frame = decoder(pkt)
                            ip = frame.data
                            break
                        except Exception as exc:
                            decode_error = exc
                    if ip is None:
                        raise ValueError(f"unable to decode packet: {decode_error}")
                else:
                    decoder = decode_map.get(datalink_type)
                    if decoder is None:
                        raise RuntimeError(f"unsupported datalink type: {datalink_type}")
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
                seq = _extract_sequence(payload)
                if seq is not None:
                    stats.netbeacon_parsed += 1
                    previous = last_seen_seq_by_source.get(source)
                    if previous is not None:
                        if seq > previous + 1:
                            stats.lost_packets += seq - previous - 1
                        elif seq == previous:
                            stats.duplicate_packets += 1
                        elif seq < previous:
                            stats.reordered_packets += 1
                    if previous is None or seq > previous:
                        last_seen_seq_by_source[source] = seq
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
        if stats_fn is not None:
            try:
                nrecv, ndrop, _nifdrop = stats_fn()
                sys.stderr.write(f"\nlibpcap received={nrecv} dropped={ndrop}\n")
            except Exception:
                if debug:
                    sys.stderr.write("\nlibpcap stats unavailable\n")
        elif debug:
            sys.stderr.write("\nlibpcap stats unavailable for this backend\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
