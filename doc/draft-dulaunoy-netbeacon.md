%%% 
title = "The NetBeacon Beacon Format"
abbrev = "NetBeacon"
ipr = "trust200902"
area = "Internet"
workgroup = "Independent"
keyword = ["netbeacon", "packet capture", "telemetry", "udp"]
docName = "draft-dulaunoy-netbeacon-format"
submissiontype = "independent"
category = "info"

[seriesInfo]
name = "Internet-Draft"
value = "draft-00"
status = "informational"
stream = "independent"

[[author]]
initials="A."
surname="Dulaunoy"
fullname="Alexandre Dulaunoy"
organization = "Independent"
[author.address]
email = "alexandre.dulaunoy@circl.lu"
%%%

.# Abstract

This document specifies NetBeacon, a compact line-oriented beacon format
carried over UDP for validating packet-capture and telemetry pipelines.
A NetBeacon message contains a header marker, sender epoch timestamp,
monotonic sequence number, and an HMAC-SHA1 signature.

NetBeacon is intended for operational diagnostics such as validating
visibility, identifying packet loss or reordering, and estimating
end-to-end capture delay.

.# Note to Readers

This Internet-Draft is derived from the implementation and documentation
maintained in the public NetBeacon repository.

{mainmatter}

# Introduction

Operators commonly need a low-cost way to test whether packet-capture
infrastructure is correctly receiving expected traffic.
In many deployments, this validation is performed by ad hoc probes with
non-standard payloads and no integrity protection.

NetBeacon defines a minimal, deterministic payload format suitable for
continuous or ad hoc checks of capture path behavior.
A sender emits signed UDP payloads at a selected cadence, and a
collector/verifier validates message authenticity and sequence continuity.

Typical operational outcomes include:

- confirming that mirrored or tapped traffic is visible to a sensor;
- estimating delay between message generation and observation;
- detecting obvious packet loss or packet reordering; and
- detecting key mismatch or payload corruption via signature failure.

# Conventions and Definitions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**",
"**NOT RECOMMENDED**", "**MAY**", and "**OPTIONAL**" in this document
are to be interpreted as described in BCP 14 [@!RFC2119] [@!RFC8174]
when, and only when, they appear in all capitals, as shown here.

# Protocol Overview

A NetBeacon sender transmits UDP [@!RFC768] datagrams containing an ASCII payload
with four semicolon-delimited fields:

~~~
header;epoch;sequence;hmac
~~~

NetBeacon does not require a session setup and does not define any
transport reliability mechanism.
Messages are independent and idempotent from a parser perspective.

The default UDP destination port used by current implementations is
12345. Deployments MAY use alternate ports.

# Message Format

## Field Definitions

A valid NetBeacon payload has exactly four fields, in order:

1. `header`: a constant marker string. Current value: `nb`.
2. `epoch`: UNIX epoch seconds in UTC (integer).
3. `sequence`: unsigned integer sequence number.
4. `hmac`: lowercase hexadecimal HMAC-SHA1 over the signed prefix.

The signed prefix is the first three fields including their delimiters
and trailing semicolon:

~~~
header;epoch;sequence;
~~~

The `hmac` field is computed using HMAC [@!RFC2104] with SHA-1
[@!RFC3174] and a pre-shared key (PSK).

## ABNF

The following ABNF [@!RFC5234] defines the textual payload:

~~~ abnf
nb-message = header ";" epoch ";" sequence ";" hmac

header     = "nb"
epoch      = 1*DIGIT
sequence   = 1*DIGIT
hmac       = 40HEXDIGLC

HEXDIGLC   = DIGIT / %x61-66 ; a-f
~~~

## Example Messages

~~~
nb;1354960619;101;335540bf3dae684c3d5cd5795fd09b9097bad656
nb;1354960619;102;56fc82c066644f179b58eb84a47e577bf92adc47
nb;1354960619;103;854207f54c1c4be97bdf4cd4a0d1068731848698
~~~

# Sender Behavior

A sender implementation:

- **MUST** construct fields in the exact order defined in this document;
- **MUST** compute HMAC over `header;epoch;sequence;` as ASCII bytes;
- **MUST** append the resulting lowercase hexadecimal digest as field 4;
- **SHOULD** increment `sequence` monotonically for each destination;
- **SHOULD** allow operator configuration of destination, PSK, rate, and
  iteration count; and
- **MAY** persist the last transmitted sequence to survive restarts.

# Receiver and Verifier Behavior

A receiver/verifier implementation:

- **MUST** parse exactly four semicolon-delimited fields;
- **MUST** reject messages failing parse or numeric conversion;
- **MUST** recompute expected HMAC from the first three fields and reject
  mismatches;
- **SHOULD** report signature validation results;
- **SHOULD** evaluate sequence continuity when historical state exists;
- **MAY** report observation delay as `now - epoch`; and
- **MAY** retain a local sequence checkpoint for continuity checks across
  process restarts.

# Operational Considerations

NetBeacon is intentionally simple and does not include negotiation,
key exchange, or retransmission.
Deployments should therefore define local operational policy for:

- beacon cadence;
- acceptable delay thresholds;
- sequence discontinuity handling; and
- sender/receiver key rotation.

When multiple senders are observed by a single verifier, operators
should partition sequence validation state by sender identity and/or
destination stream.

# Security Considerations

NetBeacon uses HMAC with a shared secret to provide integrity and origin
authentication properties for entities that know the PSK.

The protocol does not provide confidentiality, replay protection,
or resistance to traffic analysis.
An observer can read header, timestamp, and sequence metadata.

SHA-1 is used in currently deployed NetBeacon implementations for
interoperability with historical tooling.
Operators should treat this as legacy cryptographic practice and
consider migration planning toward stronger hash functions in future
specification revisions.

PSKs **MUST** be provisioned and stored securely.
Low-entropy or default keys materially reduce integrity guarantees.

# IANA Considerations

This document has no IANA actions.

# References

# Normative References

[@!RFC2104]

[@!RFC2119]

[@!RFC3174]

[@!RFC5234]

[@!RFC768]

[@!RFC8174]

# Informative References

