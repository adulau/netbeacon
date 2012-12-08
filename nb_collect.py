import dpkt
import pcap
import re
import sys

from optparse import OptionParser


usage = "usage: %prog [options]"
parser = OptionParser(usage)
parser.add_option("-i","--interface", dest="interface", help="live capture on interface (default:lo)")
parser.add_option("-r","--read", dest="filedump", help="read pcap file")
parser.add_option("-e","--extended", dest="extended", help="enable extended format including pcap timestamp")

(options, args) = parser.parse_args()

if options.interface:
    interface = options.interface
else:
    interface = "lo"

if options.filedump:
    interface = options.filedump

pc = pcap.pcap(interface)
pc.setfilter("port 12345 and udp")

decode = { pcap.DLT_LOOP:dpkt.loopback.Loopback,
           pcap.DLT_NULL:dpkt.loopback.Loopback,
           pcap.DLT_EN10MB:dpkt.ethernet.Ethernet }[pc.datalink()]

try:
    sys.stderr.write('listening on %s: %s' % (pc.name, pc.filter))
    for ts, pkt in pc:
        ip = decode(pkt).data
        udp = ip.data
        if re.search("^nb", udp.data):
            if options.extended:
                print str(ts)+"|"+udp.data
            else:
                print udp.data
except KeyboardInterrupt:
    nrecv, ndrop, nifdrop = pc.stats()
    sys.stderr.write('\n%d packets received by filter' % nrecv)
    sys.stderr.write('%d packets dropped by kernel' % ndrop)

