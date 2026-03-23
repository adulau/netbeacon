# netbeacon

`netbeacon` is a small toolkit for sending, collecting, and verifying signed UDP beacons so you can validate packet-capture pipelines.

It is useful for checking:

- beacon latency from sender to monitoring system,
- time inconsistencies between capture devices,
- packet loss or reordering, and
- basic watchdog-style health checks for packet capture.

## Python compatibility

The scripts in this repository are compatible with recent Python 3 versions and are written to run on modern CPython releases, including Python 3.10+.

## Packet format

Each UDP payload is an ASCII message with the following structure:

```text
header;epoch;sequence;hmac
```

Field meanings:

- `header`: currently always `nb`
- `epoch`: current Unix epoch timestamp in UTC
- `sequence`: unsigned integer sequence number
- `hmac`: HMAC-SHA1 signature of `header;epoch;sequence;`

By default, packets are sent to UDP port `12345`.

A pre-shared key (PSK) is shared between the sender and verifier to protect packet integrity. The default PSK is `netbeacon`, but you should set your own key in production or shared environments.

### Example messages

```text
nb;1354960619;101;335540bf3dae684c3d5cd5795fd09b9097bad656
nb;1354960619;102;56fc82c066644f179b58eb84a47e577bf92adc47
nb;1354960619;103;854207f54c1c4be97bdf4cd4a0d1068731848698
```

## Requirements

- Python 3.10 or newer recommended
- `dpkt`
- `pcap` Python bindings and a libpcap-compatible system library for packet capture

Example installation:

```bash
python3 -m pip install dpkt pcap
```

Depending on your platform, the `pcap` package may require additional system packages such as libpcap development headers.

## Scripts

### `nb_send.py`

Sends netbeacon UDP packets.

```text
Usage: nb_send.py [options]

Options:
  -h, --help            show this help message and exit
  -p PSK, --psk=PSK     pre-shared key used by the HMAC-SHA1 (default: netbeacon)
  -s, --storeseq        store sequence and validate sequence
  -i ITERATION, --iteration=ITERATION
                        set the number of iterations for sending the netbeacon
  -d DESTINATION, --destination=DESTINATION
                        set the destination(s) IPv4 address (default: 127.0.0.1)
  -v, --verbose         output netbeacon sent
```

Example:

```bash
python3 nb_send.py -s -i 3 -d 192.0.2.10 -p mysharedsecret
```

### `nb_collect.py`

Reads netbeacon packets from a live interface or a pcap source and writes decoded payloads to stdout.

```text
Usage: nb_collect.py [options]

Options:
  -h, --help            show this help message and exit
  -i INTERFACE, --interface=INTERFACE
                        live capture on interface (default: lo)
  -r FILEDUMP, --read=FILEDUMP
                        read pcap file
  -e, --extended        enable extended format including pcap timestamp
```

Examples:

```bash
python3 nb_collect.py -i eth0
python3 nb_collect.py -r capture.pcap -e
```

### `nb_verify.py`

Verifies signed netbeacon messages from stdin.

```text
Usage: nb_verify.py [options] <netbeacon messages>

Options:
  -h, --help         show this help message and exit
  -t, --timedelta    show timedelta
  -s, --storeseq     store sequence and validate sequence
  -p PSK, --psk=PSK  pre-shared key used by the HMAC-SHA1 (default: netbeacon)
```

Examples:

```bash
python3 nb_send.py -i 1 -v | python3 nb_verify.py
python3 nb_collect.py -i eth0 | python3 nb_verify.py -s -t -p mysharedsecret
```

## Typical workflow

1. Send beacons from a host on the monitored network.
2. Capture the UDP traffic where your monitoring stack can see it.
3. Pipe decoded messages into `nb_verify.py` to validate signatures and sequence continuity.
4. Use `-t` to inspect delay and `-s` to track expected ordering.

## License

`netbeacon` is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

Copyright (c) 2012,2013 Alexandre Dulaunoy - <https://github.com/adulau/>
