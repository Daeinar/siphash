class SipHash:
  def __init__(self,c=2,d=4):
    assert c >= 0 
    assert d >= 0 
    self._c = c 
    self._d = d
    self._mask = 0xffffffffffffffff

  def _parse_msg(self,m):
    l = len(m)
    self._msg = []
    n = (l//8)*8

    # parse m_0 to m_{l-2}
    for i in xrange(0, n, 8):
      s = ord(m[i])
      for j in xrange(1,8):
        s |= ord(m[i+j]) << 8*j
      self._msg.append(s)

    # parse m_{l-1}
    s = (l % 256) << 56
    for i in xrange(l-n):
      s |= ord(m[n+i]) << 8*i
    self._msg.append(s)

  def _rotl(self,v,r):
    return ( ( ( v << r ) & self._mask) | ( v >> ( 64 - r ) ) ) 

  def _sip_round(self):
    self._v[0] += self._v[1] 
    self._v[2] += self._v[3]
    self._v[2] &= self._mask
    self._v[0] &= self._mask
    self._v[1] = self._rotl(self._v[1],13)
    self._v[3] = self._rotl(self._v[3],16)
    self._v[1] ^= self._v[0] 
    self._v[3] ^= self._v[2] 
    self._v[0] = self._rotl(self._v[0],32)
    self._v[2] += self._v[1]
    self._v[0] += self._v[3]
    self._v[2] &= self._mask
    self._v[0] &= self._mask
    self._v[1] = self._rotl(self._v[1],17)
    self._v[3] = self._rotl(self._v[3],21)
    self._v[1] ^= self._v[2]
    self._v[3] ^= self._v[0]
    self._v[2] = self._rotl(self._v[2],32)

  def hash(self,m,k):
    self._k = [k & 0xffffffffffffffff, k >> 64]

    # initialization
    self._v = [self._k[0] ^ 0x736f6d6570736575, self._k[1] ^ 0x646f72616e646f6d,
               self._k[0] ^ 0x6c7967656e657261, self._k[1] ^ 0x7465646279746573]

    self._parse_msg(m)

    # compression
    for i in xrange(len(self._msg)):
      self._v[3] ^= self._msg[i]
      for j in xrange(self._c):
        self._sip_round()
      self._v[0] ^= self._msg[i]
    
    # finalization
    self._v[2] ^= 0xff
    for i in xrange(self._d):
      self._sip_round()

    return self._v[0] ^ self._v[1] ^ self._v[2] ^ self._v[3]
