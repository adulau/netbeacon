import socket
import datetime
import time
import sys

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
        if message_keys[i] == "epoch":
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

for line in sys.stdin:
    line = line.rstrip()
    m = {}
    m = nbparse(message=line)
    print m['hmac']
    message = m['header']+";"+str(m['epoch'])+";"+m['sequence']+";"
    if m['hmac'] == nbsign(message=message):
        print "valid signature for "+message
        timedelta = deltafromnow(epoch=m['epoch'])
        print "Time delay "+str(timedelta)
    else:
        print "(!) invalid signature for "+message

    #signature = line.rsplit(';')[-1:]
