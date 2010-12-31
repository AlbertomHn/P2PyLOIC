#!/usr/bin/env python
import uuid,random
from collections import deque
import asyncore,socket

from openssl import DSA
from nettoken import NetworkToken

from hashlib import sha256
from base64 import b64encode
asyn_map = {}

packets = {
    'j': 'PACKET_NET_JOIN',
    'k': 'PACKET_JOIN_ACK'
}

ps = {}
for k in packets: ps[packets[k]] = k


class Client(asyncore.dispatcher):
    """main class"""
    def __init__(self, port):
        asyncore.dispatcher.__init__(self, map=asyn_map)
        self.write_buffer = deque()
        
        # setup socket
        self.create_socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.bind(("", port))
        self.set_reuse_addr()
        
        # generate unique id
        self.uuid = uuid.uuid4()
        
        self.port = port
        self.key = None
        self.entrynodes = []
        
    def sendData(self, target, data):
        self.write_buffer.append((target, data))

    def handle_read(self):
        data, target = self.recvfrom(4096)
        if data[0] in packets:
            try:
                packettype = packets[data[0]]
                
                if packettype == 'PACKET_NET_JOIN':
                    keyhash = data[1:33]
                    unique_id = data[33:]
                    if keyhash != self.keyhash or unique_id == self.uuid.bytes:
                        print "invalid packet from",target
                        return
                    print "got join from",target
                    self.sendPublicKey(target)
                if packettype == 'PACKET_JOIN_ACK':
                    key = data[1:]
                    if not self.key is None or self.keyhash != sha256(key).digest():
                        print "invalid key from",target
                        return
                    self.load_public_key(key)
                    print "got key:"
                    print b64encode(key)
            except Exception,e: print e
        else:
            print ("got %s from"%repr(data)),target
    def handle_write(self):
        target, data = self.write_buffer.popleft()
        sent = self.sendto(data, target)
        data = data[sent:]
        if len(data) > 0:
            self.write_buffer.appendleft((target, data))
    def writable(self):
        return len(self.write_buffer) > 0
    def readable(self):
        return True
        
    def load_private_key(self, private_key):
        self.key = DSA(privkey=private_key)
        self.keyhash = sha256(self.key.get_pubkey()).digest()
    def load_public_key(self, public_key):
        self.key = DSA(pubkey=public_key)
        self.keyhash = sha256(public_key).digest()
    def load_nettoken(self, token):
        token = NetworkToken(token=token)
        self.keyhash = token.keyhash
        self.entrynodes.append((token.ip_addr, token.port))
    def save_nettoken(self, publicip):
        return str(NetworkToken(self.keyhash, publicip, self.port))
    def sendNetJoin(self, target):
        p = ps['PACKET_NET_JOIN'] + self.keyhash + self.uuid.get_bytes() 
        self.sendData(target, p)
    def sendPublicKey(self, target):
        p = ps['PACKET_JOIN_ACK'] + self.key.get_pubkey()
        self.sendData(target, p)

def main():
    port = random.randrange(1024, 65535)
    print "using port",port
    c = Client(port)
    import sys
    if sys.argv[1] == "keygen":
        dsa = DSA(generate = True)
        sys.stdout.write("======PUBLIC  KEY======\n")
        sys.stdout.write(b64encode(dsa.get_pubkey()))
        sys.stdout.write("\n======PRIVATE KEY======\n")
        sys.stdout.write(b64encode(dsa.get_privkey()))
        sys.stdout.write("\n=======================\n")
        sys.stdout.flush()
        c.load_private_key(dsa.get_privkey())
        print "token:", c.save_nettoken("127.0.0.1")
    elif len(sys.argv[1]) == 52:
        print "loading token",sys.argv[1]
        c.load_nettoken(sys.argv[1])
        c.sendNetJoin(c.entrynodes[0])
    asyncore.loop(3, map=asyn_map)

if __name__ == '__main__':
    main()

