import struct

class MPI(object):
    def __init__(self, datum):
        if type(datum) in [int, long]:
            self.num = datum
        elif type(datum) is str:
            self.num, rest = self._decode(datum)
        else:
            raise TypeError("Must be called with an int or long, or a string representing an MPI")

    def __str__(self):
        return self._encode(self.num)

    def __repr__(self):
        return "MPI<0x{0:X}>".format(self.num)

    def __long__(self):
        return self.num

    @classmethod
    def _decode(cls, blob):
        bitlen, = struct.unpack("!H", blob[:2])
        strlen = int((bitlen + 7) / 8)
        mpi = blob[2:2+strlen]
        i = 0L
        for n in list(mpi):
            i <<= 8
            i += ord(n)
        return (i, blob[2+strlen:])

    @classmethod
    def _encode(cls, num):
        bitlen = len(bin(num)[2:])
        hexed = hex(num)[2:-1]
        if len(hexed) % 2 == 1:
            hexed = "0" + hexed
        return struct.pack("!H", bitlen) + hexed.decode('hex')

class Packet(object):
    tag = 0
    def __init__(self, body):
        self.body = body

    def __str__(self):
        return self._encode(self.tag, self.body)

    @classmethod
    def _encodeNew(cls, tag, body):
        l = len(body)
        ll = False
        t = struct.pack("B", 0xc0 | tag)
        if l < 192:
            ll = struct.pack("B", l)
        elif l <= 8383:
            ll = struct.pack("!H", (((l >> 8)+192) << 8) + (l & 0xff) - 192)
        else:
            raise NotImplementedError("Partial Body Length encoding not implemented")
        return t + ll + body

    @classmethod
    def _encodeOld(cls, tag, body):
        l = len(body)
        t = 0x80 + (tag << 2)
        if l < 255:
            ll = struct.pack("B", l)
        elif l < 0xffff:
            ll = struct.pack("!H", l)
            t += 1
        elif l < 0xffffffff:
            ll = struct.pack("!I", l)
            t += 2
        else:
            raise ValueError("Unsupported body length for old encoding")
        return chr(t) + ll + body

    @classmethod
    def _encode(cls, tag, body, hint = None):
        if hint:
            if hint == 'old':
                return cls._encodeOld(tag, body)
            elif hint == 'new':
                return cls._encodeNew(tag, body)
            else:
                raise ValueError("Unrecognized encoding hint")
        if tag < 15: # Prefer old encoding if possible.
            return cls._encodeOld(tag, body)
        else:
            return cls._encodeNew(tag, body)

class PublicKeyPacket(Packet):
    tag = 6

class PrivateKeyPacket(PublicKeyPacket):
    tag = 5

class PublicSubkeyPacket(PublicKeyPacket):
    tag = 14

class PrivateSubkeyPacket(PrivateKeyPacket):
    tag = 7

class UserIDPacket(Packet):
    tag = 13
    def __init__(self, uid):
        self.uid = uid

    def __str__(self):
        return self._encode(self.tag, self.uid)

    def __repr__(self):
        return 'UserID<"{0}">'.format(self.uid)

class SignaturePacket(Packet):
    tag = 2

class Message(object):
    def __init__(self, body = None):
        if type(body) is str:
            self.packets = self._parse(body)
        elif type(body) in (list, tuple):
            self.packets = list(body)
        elif body is None:
            self.packets = []
        else:
            raise TypeError(type(body))

    def _parse(cls, blob):
        ret = []
        while blob:
            head = ord(blob[0])
            if not (head & (1 << 7)):
                raise ValueError("Malformed header detected")
            if head & (1 << 6): # New format
                tag = head & 0x1f
                l = ord(blob[1])
                if l < 192:
                    blob = blob[2:]
                elif l >= 192 and l <= 223:
                    l -= 192
                    l <<= 8
                    l += ord(blob[2])
                    l += 192
                    blob = blob[3:]
                elif l == 255:
                    l = ord(blob[2])
                    l <<= 8
                    l += ord(blob[3])
                    l <<= 8
                    l += ord(blob[4])
                    l <<= 8
                    l += ord(blob[5])
                    blob = blob[6:]
                else:
                    raise NotImplementedError("Partial Body Length encoding not implemented")
            else: # Old format
                tag = (head >> 2) & 0xf
                ll = head & 0b11
                l = 0
                if ll == 0:
                    l = ord(blob[1])
                    blob = blob[2:]
                elif ll == 1:
                    l = ord(blob[1])
                    l <<= 8
                    l += ord(blob[2])
                    blob = blob[3:]
                elif ll == 2:
                    l = ord(blob[1])
                    l <<= 8
                    l += ord(blob[2])
                    l <<= 8
                    l += ord(blob[3])
                    l <<= 8
                    l += ord(blob[4])
                    blob = blob[5:]
                else:
                    raise NotImplementedError("Indeterminate length encoding not implemented")
            ret.append(cls.tagToCls(tag)(blob[:l]))
            blob = blob[l:]
        return ret

    @classmethod
    def tagToCls(cls, tag):
        if tag == 2:
            return SignaturePacket
        elif tag == 6:
            return PublicKeyPacket
        elif tag == 13:
            return UserIDPacket
        raise NotImplementedError("Unimplemented tag {0}".format(tag))

    def __str__(self):
        return "".join(map(lambda p: str(p), self.packets))

    def __repr__(self):
        return "Message<{0}>".format(len(self.packets))
