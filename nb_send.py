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
def nbmessage(seq=1):
    m = ""
    m = m + "nb"
    m = m + ";"
    t = datetime.datetime.now()
    now = time.mktime(t.timetuple())
    m = m + (str(int(now)))
    m = m + ";"
    m = m + str(seq)
    m = m + ";"
    m = m + nbsign(message=m)
    return m

def nbsend(destination=None,payload=None, logging=False):
    if destination is None:
        return False
    if logging:
        print (payload)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.sendto(payload, (destination, 12345))
    return True

usage = "usage: %prog [options] <netbeacon messages>"
parser = OptionParser(usage)
parser.add_option("-s","--storeseq", dest="storeseq", action='store_true', help="store sequence and validate sequence")

(options, args) = parser.parse_args()

if options.storeseq:
    import shelve
    s = shelve.open("netbeacon-send.seq")
    if 'seq' not in s:
        s['seq'] = 1
        seqstart = s['seq']
    else:
        seqstart = s['seq']
else:
    seqstart = 1

for x in range(seqstart,seqstart+10):
    nbsend(destination="127.0.0.1", payload=nbmessage(x), logging=True)
    if options.storeseq:
        s['seq'] = x
if options.storeseq:
    s.close()
