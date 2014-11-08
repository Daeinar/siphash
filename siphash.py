"""
   SipHash reference python implementation.
   ------

   :copyright: (c) 2013-2014 by Philipp Jovanovic <philipp@jovanovic.io>.
   :license: MIT, see LICENSE for more details.
"""
class SipHash:

    def __init__(self,c=2,d=4):
        assert c >= 0
        assert d >= 0
        self.c = c
        self.d = d
        self.mask = 0xffffffffffffffff

    def __call__(self,m,k):
        assert k >= 0 and k < (1 << 128)
        self.k = [k & self.mask, k >> 64]

        # initialization
        self.v = [self.k[0] ^ 0x736f6d6570736575, self.k[1] ^ 0x646f72616e646f6d,
                  self.k[0] ^ 0x6c7967656e657261, self.k[1] ^ 0x7465646279746573]

        self.parse_msg(m)

        # compression
        for i in xrange(len(self.msg)):
            self.v[3] ^= self.msg[i]
            for j in xrange(self.c):
                self.sip_round()
            self.v[0] ^= self.msg[i]

        # finalization
        self.v[2] ^= 0xff
        for i in xrange(self.d):
            self.sip_round()

        return self.v[0] ^ self.v[1] ^ self.v[2] ^ self.v[3]

    def parse_msg(self,m):
        l = len(m)
        self.msg = []
        n = (l//8)*8

        # parse m_0 to m_{l-2}
        for i in xrange(0, n, 8):
            s = ord(m[i])
            for j in xrange(1,8):
                s |= ord(m[i+j]) << 8*j
            self.msg.append(s)

        # parse m_{l-1}
        s = (l % 256) << 56
        for i in xrange(l-n):
            s |= ord(m[n+i]) << 8*i
        self.msg.append(s)

    def rotl(self,v,r):
        return ( ( ( v << r ) & self.mask) | ( v >> ( 64 - r ) ) )

    def sip_round(self):
        self.v[0] += self.v[1]
        self.v[2] += self.v[3]
        self.v[2] &= self.mask
        self.v[0] &= self.mask
        self.v[1] = self.rotl(self.v[1],13)
        self.v[3] = self.rotl(self.v[3],16)
        self.v[1] ^= self.v[0]
        self.v[3] ^= self.v[2]
        self.v[0] = self.rotl(self.v[0],32)
        self.v[2] += self.v[1]
        self.v[0] += self.v[3]
        self.v[2] &= self.mask
        self.v[0] &= self.mask
        self.v[1] = self.rotl(self.v[1],17)
        self.v[3] = self.rotl(self.v[3],21)
        self.v[1] ^= self.v[2]
        self.v[3] ^= self.v[0]
        self.v[2] = self.rotl(self.v[2],32)
