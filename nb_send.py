import socket
import datetime
import time
from optparse import OptionParser

try:
    from hashlib import sha1
except ImportError:
    from sha import sha as sha1
import hmac

## nb;epochvalue;sq;hmac
## hmacfunc("nb;epochvalue;sq;", psk)
def nbsign(message=None, psk="netbeacon"):
    auth = hmac.new(psk, message, sha1)
    return auth.hexdigest()

# format: nb;1354687980;1;500f5e18df881bb1dd22ee3c468209669a13e4ef
def nbmessage(seq=1, psk="netbeacon"):
    m = ""
    m = m + "nb"
    m = m + ";"
    t = datetime.datetime.now()
    now = time.mktime(t.timetuple())
    m = m + (str(int(now)))
    m = m + ";"
    m = m + str(seq)
    m = m + ";"
    m = m + nbsign(message=m,psk=psk)
    return m

def nbsend(destination=None,payload=None, logging=False):
    if destination is None:
        return False
    if logging:
        print (payload)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.sendto(payload, (destination, 12345))
    return True

usage = "usage: %prog [options]"
parser = OptionParser(usage)
parser.add_option("-p","--psk", dest="psk", help="pre-shared key used by the HMAC-SHA1 (default: netbeacon)")
parser.add_option("-s","--storeseq", dest="storeseq", action='store_true', help="store sequence and validate sequence")
parser.add_option("-i","--iteration", dest="iteration", type=int, help="set the number of interation for sending the netbeacon")
parser.add_option("-d","--destination", dest="destinations", action="append", help="set the destination(s) IPv4 address (default: 127.0.0.1)")
parser.add_option("-v","--verbose", dest="verbose", action='store_true', help="output netbeacon sent")
(options, args) = parser.parse_args()

if options.psk:
    psk = options.psk
else:
    psk = "netbeacon"

destinations = []

if not options.destinations:
    destinations.append("127.0.0.1")
else:
    for v in options.destinations:
        destinations.append(v)

if options.storeseq:
    import shelve
    s = shelve.open("netbeacon-send.seq")
    for destination in destinations:
        k = 'seq:' + str(destination)
        if logging:
            print (k)
        if k not in s:
            s[k] = 1
        seqstart = s[k]+1
else:
    seqstart = 1

if not options.iteration:
    options.iteration=10

for destination in destinations:
    for x in range(seqstart,seqstart+options.iteration):
        nbsend(destination=destination, payload=nbmessage(x, psk=psk), logging=options.verbose)
        if options.storeseq:
            s['seq:'+str(destination)] = x

if options.storeseq:
    s.close()
