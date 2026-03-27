#!/usr/bin/env python3
"""Verify netbeacon messages from stdin."""

from __future__ import annotations

import datetime
import hmac
import shelve
import sys
import time
from dataclasses import dataclass
from hashlib import sha1
from optparse import OptionParser

DEFAULT_PSK = "netbeacon"
SEQUENCE_DB = "netbeacon.seq"
MESSAGE_KEYS = ["header", "epoch", "sequence", "hmac"]


@dataclass
class VerifyStats:
    """Track verification counters for live monitoring and summaries."""

    received: int = 0
    analyzed: int = 0
    valid_signature: int = 0
    invalid_signature: int = 0
    parse_errors: int = 0
    sequence_ok: int = 0
    sequence_nok: int = 0


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
            try:
                parsed[key] = int(value)
            except ValueError:
                return False
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


def _emit_stats(stats: VerifyStats, started_at: float, label: str = "stats") -> None:
    elapsed = max(time.time() - started_at, 0.000001)
    sys.stderr.write(
        f"\n[{label}] received={stats.received} analyzed={stats.analyzed} valid={stats.valid_signature} "
        f"invalid={stats.invalid_signature} parse_errors={stats.parse_errors} "
        f"seq_ok={stats.sequence_ok} seq_nok={stats.sequence_nok} rate={stats.received / elapsed:.2f} msg/s"
    )


def main() -> int:
    usage = "usage: %prog [options] <netbeacon messages>"
    parser = OptionParser(usage)
    parser.add_option("-t", "--timedelta", dest="timedelta", action="store_true", help="show timedelta")
    parser.add_option("-s", "--storeseq", dest="storeseq", action="store_true", help="store sequence and validate sequence")
    parser.add_option("-p", "--psk", dest="psk", help=f"pre-shared key used by the HMAC-SHA1 (default: {DEFAULT_PSK})")
    parser.add_option("-m", "--monitor", dest="monitor", action="store_true", help="emit periodic live verification stats to stderr")
    parser.add_option("--monitor-every", dest="monitor_every", type=int, default=10, help="emit live stats every N messages (default: 10)")
    parser.add_option("--debug", dest="debug", action="store_true", help="light debug output with final summary")
    parser.add_option("--debug-full", dest="debug_full", action="store_true", help="full debug output including per-message traces")
    options, _args = parser.parse_args()

    psk = options.psk or DEFAULT_PSK
    sequence_store = shelve.open(SEQUENCE_DB) if options.storeseq else None
    stats = VerifyStats()
    started_at = time.time()
    monitor_every = max(int(options.monitor_every or 1), 1)
    debug = bool(options.debug or options.debug_full)

    try:
        for line in sys.stdin:
            line = line.rstrip()
            stats.received += 1
            parsed = nbparse(message=line)
            if not parsed:
                stats.parse_errors += 1
                print(f"(!) invalid message format: {line}")
                if options.debug_full:
                    sys.stderr.write(f"[debug-full] parse failed at message {stats.received}\n")
                continue

            stats.analyzed += 1
            message = f"{parsed['header']};{parsed['epoch']};{parsed['sequence']};"
            expected_hmac = nbsign(message=message, psk=psk)
            if parsed["hmac"] == expected_hmac:
                stats.valid_signature += 1
                print(f"valid signature for {message}")
                if options.timedelta:
                    print(f"Time delay {deltafromnow(epoch=int(parsed['epoch']))}")
                if sequence_store is not None:
                    seq = validateseq(sequence_store, int(parsed["sequence"]))
                    if seq:
                        stats.sequence_ok += 1
                        print(f"Sequence ok {seq}")
                    else:
                        stats.sequence_nok += 1
                        print(
                            f"Sequence nok - received ({parsed['sequence']}) expected ({sequence_store['seq'] + 1})"
                        )
            else:
                stats.invalid_signature += 1
                print(f"(!) invalid signature for {message}")

            if options.debug_full:
                sys.stderr.write(
                    f"[debug-full] message={stats.received} sequence={parsed['sequence']} "
                    f"valid={parsed['hmac'] == expected_hmac}\n"
                )

            if options.monitor and stats.received % monitor_every == 0:
                _emit_stats(stats, started_at, label="monitor")
    finally:
        if sequence_store is not None:
            if "seq" in sequence_store:
                sequence_store["seq"] = sequence_store["seq"] - 1
            sequence_store.close()
        if debug or options.monitor:
            _emit_stats(stats, started_at, label="final")
            sys.stderr.write("\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
