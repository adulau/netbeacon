#!/usr/bin/env python3
"""Collect netbeacon UDP packets from a live interface or pcap input."""

from __future__ import annotations

import re
import socket
import sys
from optparse import OptionParser

NETBEACON_PATTERN = re.compile(r"^nb")


def decode_payload(payload: bytes) -> str:
    """Decode a UDP payload to text if possible."""
    return payload.decode("ascii", errors="replace")


def main() -> int:
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-i", "--interface", dest="interface", help="live capture on interface (default: lo)")
    parser.add_option("-r", "--read", dest="filedump", help="read pcap file")
    parser.add_option("-e", "--extended", dest="extended", action="store_true", help="enable extended format including pcap timestamp")
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

    try:
        sys.stderr.write(f"listening on {pc.name}: {pc.filter}")
        for ts, pkt in pc:
            frame = decoder(pkt)
            ip = frame.data
            udp = ip.data
            payload = decode_payload(udp.data)
            if NETBEACON_PATTERN.search(payload):
                if options.extended:
                    print(f"{ts}|{socket.inet_ntoa(ip.src)}|{payload}")
                else:
                    print(payload)
    except KeyboardInterrupt:
        nrecv, ndrop, _nifdrop = pc.stats()
        sys.stderr.write(f"\n{nrecv} packets received by filter")
        sys.stderr.write(f"{ndrop} packets dropped by kernel")

    return 0


if __name__ == "__main__":
    sys.exit(main())
