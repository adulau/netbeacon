
netbeacon - monitoring your network capture
===========================================

netbeacon is a set of free software tools to send beacons over
the network to test the accuracy and the precision of your network
capture framework. With netbeacon you can test the following properties
of your network capture (e.g. for honeypot packet data capture,
data interception devices, NIDS, DPI ...):

- How long it takes for a packet to reach your monitoring.
- Time inconsistencies between devices.
- Finding missing packets or its (re)ordering.
- Watchdog to verify an operational network capture.

netbeacon - packet format
-------------------------

The netbeacon format is a simple ASCII format encapsulated in an UDP
packet. The format is the following:

header;epoch;sequence;hmac

The current header is nb
The epoch value (in UTC format)
The sequence an unsigned integer
and the HMAC-SHA1 signature.

Each message is encapsulated in UDP and by default using port 12345.

A pre-shared key (PSK) is agreed between the netbeacon sender
and netbeacon recipient to ensure packet integrity using HMAC (SHA1).
There is a default key "netbeacon" but we highly recommend to set your
own for your systems.

sample netbeacon messages
+++++++++++++++++++++++++

Here is a serie of 3 netbeacon messages extracted from 3 UDP packets:
 
        nb;1354960619;101;335540bf3dae684c3d5cd5795fd09b9097bad656
        nb;1354960619;102;56fc82c066644f179b58eb84a47e577bf92adc47
        nb;1354960619;103;854207f54c1c4be97bdf4cd4a0d1068731848698

netbeacon - usage
-----------------

nb_send.py
++++++++++

        Usage: nb_send.py [options]

        Options:
          -h, --help            show this help message and exit
          -p PSK, --psk=PSK     pre-shared key used by the HMAC-SHA1 (default:
                                netbeacon)
          -s, --storeseq        store sequence and validate sequence
          -i ITERATION, --iteration=ITERATION
                                set the number of interation for sending the netbeacon
          -d DESTINATION, --destination=DESTINATION
                                set the destination IPv4 address (default: 127.0.0.1)
          -v, --verbose         output netbeacon sent


nb_collect.py
+++++++++++++

        Usage: nb_collect.py [options]

        Options:
          -h, --help            show this help message and exit
          -i INTERFACE, --interface=INTERFACE
                                live capture on interface (default:lo)
          -r FILEDUMP, --read=FILEDUMP
                                read pcap file
          -e EXTENDED, --extended=EXTENDED
                                enable extended format including pcap timestamp

nb_verify.py
++++++++++++

        Usage: nb_verify.py [options] <netbeacon messages>

        Options:
          -h, --help         show this help message and exit
          -t, --timedelta    show timedelta
          -s, --storeseq     store sequence and validate sequence
          -p PSK, --psk=PSK  pre-shared key used by the HMAC-SHA1 (default: netbeacon)


License
=======

netbeacon is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Copyright (c) 2012 Alexandre Dulaunoy - https://github.com/adulau/
