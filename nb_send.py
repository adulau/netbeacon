#!/usr/bin/env python3
"""Send netbeacon UDP beacons."""

from __future__ import annotations

import datetime
import hmac
import shelve
import socket
import sys
import time
from hashlib import sha1
from optparse import OptionParser
from typing import Iterable

DEFAULT_PSK = "netbeacon"
DEFAULT_PORT = 12345
DEFAULT_DESTINATION = "127.0.0.1"
DEFAULT_ITERATIONS = 10
SEQUENCE_DB = "netbeacon-send.seq"


def nbsign(message: str, psk: str = DEFAULT_PSK) -> str:
    """Return the HMAC-SHA1 signature for a netbeacon payload prefix."""
    return hmac.new(psk.encode("utf-8"), message.encode("ascii"), sha1).hexdigest()


def nbmessage(seq: int = 1, psk: str = DEFAULT_PSK) -> str:
    """Build a netbeacon message for the provided sequence number."""
    now = int(time.mktime(datetime.datetime.now(datetime.timezone.utc).timetuple()))
    message = f"nb;{now};{seq};"
    return f"{message}{nbsign(message=message, psk=psk)}"


def nbsend(destination: str, payload: str, logging: bool = False) -> bool:
    """Send a UDP netbeacon payload to the configured destination."""
    if not destination:
        return False
    if logging:
        print(payload)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.sendto(payload.encode("ascii"), (destination, DEFAULT_PORT))
    finally:
        sock.close()
    return True


def _load_destinations(values: Iterable[str] | None) -> list[str]:
    if not values:
        return [DEFAULT_DESTINATION]
    return list(values)


def main() -> int:
    usage = "usage: %prog [options]"
    parser = OptionParser(usage)
    parser.add_option("-p", "--psk", dest="psk", help=f"pre-shared key used by the HMAC-SHA1 (default: {DEFAULT_PSK})")
    parser.add_option("-s", "--storeseq", dest="storeseq", action="store_true", help="store sequence and validate sequence")
    parser.add_option("-i", "--iteration", dest="iteration", type=int, help="set the number of iterations for sending the netbeacon")
    parser.add_option("-d", "--destination", dest="destinations", action="append", help=f"set the destination(s) IPv4 address (default: {DEFAULT_DESTINATION})")
    parser.add_option("-v", "--verbose", dest="verbose", action="store_true", help="output netbeacon sent")
    options, _args = parser.parse_args()

    psk = options.psk or DEFAULT_PSK
    destinations = _load_destinations(options.destinations)
    iteration_count = options.iteration or DEFAULT_ITERATIONS

    sequence_starts = {destination: 1 for destination in destinations}
    sequence_store = None
    if options.storeseq:
        sequence_store = shelve.open(SEQUENCE_DB)
        for destination in destinations:
            key = f"seq:{destination}"
            if options.verbose:
                print(key)
            if key not in sequence_store:
                sequence_store[key] = 0
            sequence_starts[destination] = sequence_store[key] + 1

    try:
        for destination in destinations:
            start = sequence_starts[destination]
            for seq in range(start, start + iteration_count):
                nbsend(destination=destination, payload=nbmessage(seq, psk=psk), logging=bool(options.verbose))
                if sequence_store is not None:
                    sequence_store[f"seq:{destination}"] = seq
    finally:
        if sequence_store is not None:
            sequence_store.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
