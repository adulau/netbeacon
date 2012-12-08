import socket
import datetime
import time
import sys
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

message_keys = ['header','epoch','sequence','hmac']

def nbparse(message=None):
    if message is None:
        return False
    i = 0
    m = {}
    for v in line.rsplit(';'):
        if message_keys[i] == "epoch" or message_keys[i] == "sequence":
            m[message_keys[i]] = int(v)
        else:
            m[message_keys[i]] = v
        i = i +1
    return m

def deltafromnow(epoch=None):
    if epoch is None:
        return False
    t = datetime.datetime.now()
    now = time.mktime(t.timetuple())
    return now-epoch

def validateseq(seq=None, update=True):
    if seq is None:
        return False
    if not 'seq' in s:
        s['seq'] = seq
        return s['seq']
    elif seq == (s['seq']+1):
        s['seq'] = s['seq'] + 1
        return s['seq']
    else:
        return False

usage = "usage: %prog [options] <netbeacon messages>"
parser = OptionParser(usage)
#parser.add_option("-i","--id", dest="id", help="id of the netbeacon message processed")
parser.add_option("-t","--timedelta",dest="timedelta",  action='store_true', help="show timedelta")
parser.add_option("-s","--storeseq", dest="storeseq", action='store_true', help="store sequence and validate sequence")
parser.add_option("-p","--psk", dest="psk", help="pre-shared key used by the HMAC-SHA1 (default: netbeacon)")

(options, args) = parser.parse_args()

if options.psk:
    psk = options.psk
else:
    psk = "netbeacon"

if options.storeseq:
    import shelve
    s = shelve.open("netbeacon.seq")

for line in sys.stdin:
    line = line.rstrip()
    m = {}
    m = nbparse(message=line)
    print m['hmac']
    message = m['header']+";"+str(m['epoch'])+";"+str(m['sequence'])+";"
    if m['hmac'] == nbsign(message=message, psk=psk):
        print "valid signature for "+message
        if options.timedelta:
            timedelta = deltafromnow(epoch=m['epoch'])
            print "Time delay "+str(timedelta)
        if options.storeseq:
            seq = validateseq(seq=m['sequence'])
            if seq:
                print "Sequence ok "+str(seq)
            else:
                print "Sequence nok - received ("+str(m['sequence'])+") expected ("+str(s['seq']+1)+")"
    else:
        print "(!) invalid signature for "+message

if options.storeseq:
    s['seq'] = s['seq']-1
    s.close()
