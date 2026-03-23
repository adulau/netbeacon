#!/usr/bin/env python3
"""Verify netbeacon messages from stdin."""

from __future__ import annotations

import datetime
import hmac
import shelve
import sys
import time
from hashlib import sha1
from optparse import OptionParser

DEFAULT_PSK = "netbeacon"
SEQUENCE_DB = "netbeacon.seq"
MESSAGE_KEYS = ["header", "epoch", "sequence", "hmac"]


def nbsign(message: str, psk: str = DEFAULT_PSK) -> str:
    """Return the HMAC-SHA1 signature for a netbeacon payload prefix."""
    return hmac.new(psk.encode("utf-8"), message.encode("ascii"), sha1).hexdigest()


def nbparse(message: str) -> dict[str, int | str] | bool:
    """Parse a netbeacon message into its component fields."""
    if not message:
        return False

    parts = message.rsplit(";")
    if len(parts) != len(MESSAGE_KEYS):
        return False

    parsed: dict[str, int | str] = {}
    for index, value in enumerate(parts):
        key = MESSAGE_KEYS[index]
        if key in {"epoch", "sequence"}:
            parsed[key] = int(value)
        else:
            parsed[key] = value
    return parsed


def deltafromnow(epoch: int) -> float:
    """Return the seconds elapsed since the beacon epoch."""
    now = time.mktime(datetime.datetime.now(datetime.timezone.utc).timetuple())
    return now - epoch


def validateseq(store, seq: int):
    """Validate and update the saved sequence number."""
    if "seq" not in store:
        store["seq"] = seq
        return store["seq"]
    if seq == (store["seq"] + 1):
        store["seq"] = store["seq"] + 1
        return store["seq"]
    return False


def main() -> int:
    usage = "usage: %prog [options] <netbeacon messages>"
    parser = OptionParser(usage)
    parser.add_option("-t", "--timedelta", dest="timedelta", action="store_true", help="show timedelta")
    parser.add_option("-s", "--storeseq", dest="storeseq", action="store_true", help="store sequence and validate sequence")
    parser.add_option("-p", "--psk", dest="psk", help=f"pre-shared key used by the HMAC-SHA1 (default: {DEFAULT_PSK})")
    options, _args = parser.parse_args()

    psk = options.psk or DEFAULT_PSK
    sequence_store = shelve.open(SEQUENCE_DB) if options.storeseq else None

    try:
        for line in sys.stdin:
            line = line.rstrip()
            parsed = nbparse(message=line)
            if not parsed:
                print(f"(!) invalid message format: {line}")
                continue

            message = f"{parsed['header']};{parsed['epoch']};{parsed['sequence']};"
            expected_hmac = nbsign(message=message, psk=psk)
            if parsed["hmac"] == expected_hmac:
                print(f"valid signature for {message}")
                if options.timedelta:
                    print(f"Time delay {deltafromnow(epoch=int(parsed['epoch']))}")
                if sequence_store is not None:
                    seq = validateseq(sequence_store, int(parsed["sequence"]))
                    if seq:
                        print(f"Sequence ok {seq}")
                    else:
                        print(
                            f"Sequence nok - received ({parsed['sequence']}) expected ({sequence_store['seq'] + 1})"
                        )
            else:
                print(f"(!) invalid signature for {message}")
    finally:
        if sequence_store is not None:
            if "seq" in sequence_store:
                sequence_store["seq"] = sequence_store["seq"] - 1
            sequence_store.close()

    return 0


if __name__ == "__main__":
    sys.exit(main())
