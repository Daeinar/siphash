"""
   SipHash reference python implementation.
   ------

   :copyright: (c) 2013-2014 by Philipp Jovanovic <philipp@jovanovic.io>.
   :license: MIT, see LICENSE for more details.
"""

from struct import pack, unpack

class SipHash:

    def __init__(self,c=2,d=4,h=8):
        assert c >= 0
        assert d >= 0
        assert h in [8,16]
        self.x = { 8: (0x00,0xff,0x00), 16: (0xee,0xee,0xdd) }
        self.c = c
        self.d = d
        self.h = h
        self.mask = 0xffffffffffffffff
        self.ds = self.x[h]

    def __call__(self,m,k):
        assert len(k) == 16
        msg = self.parse_msg(m)
        key = [self.load(k[0:8]), self.load(k[8:16])]
        tag = ''

        # initialization
        self.v = [key[0] ^ 0x736f6d6570736575, key[1] ^ 0x646f72616e646f6d,
                  key[0] ^ 0x6c7967656e657261, key[1] ^ 0x7465646279746573]

        self.v[1] ^= self.ds[0]

        # compression
        for i in xrange(len(msg)):
            self.v[3] ^= msg[i]
            for j in xrange(self.c):
                self.sip_round()
            self.v[0] ^= msg[i]

        # finalization
        self.v[2] ^= self.ds[1]
        for i in xrange(1,self.h/8+1):
            if i == 2:
                self.v[1] ^= self.ds[2]
            for j in xrange(self.d):
                self.sip_round()
            tag += self.store(self.v[0] ^ self.v[1] ^ self.v[2] ^ self.v[3])

        return tag

    def load(self, x):
        return unpack('<Q', x)[0]

    def store(self, x):
        return pack('<Q', x)

    def parse_msg(self,m):
        l = len(m)
        n = (l//8)*8
        msg = []

        # parse m_0 to m_{l-2}
        for i in xrange(0, n, 8):
            s = ord(m[i])
            for j in xrange(1,8):
                s |= ord(m[i+j]) << 8*j
            msg.append(s)

        # parse m_{l-1}
        s = (l % 256) << 56
        for i in xrange(l-n):
            s |= ord(m[n+i]) << 8*i
        msg.append(s)

        return msg

    def rotl(self,v,r):
        return ( ( ( v << r ) & self.mask) | ( v >> ( 64 - r ) ) )

    def sip_round(self):
        v = self.v
        v[0] = (v[0] + v[1]) & self.mask
        v[2] = (v[2] + v[3]) & self.mask
        v[1] = self.rotl(v[1],13)
        v[3] = self.rotl(v[3],16)
        v[1] ^= v[0]
        v[3] ^= v[2]
        v[0] = self.rotl(v[0],32)
        v[2] = (v[1] + v[2]) & self.mask
        v[0] = (v[0] + v[3]) & self.mask
        v[1] = self.rotl(v[1],17)
        v[3] = self.rotl(v[3],21)
        v[1] ^= v[2]
        v[3] ^= v[0]
        v[2] = self.rotl(v[2],32)
