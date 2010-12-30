"""
This module contains a class for network-token parsing and generation.

@see: U{http://piratepad.net/pyloicp2p}
"""
import socket,hashlib,struct
from base64 import b64encode, b64decode

class NetworkToken(object):
    """
    Class that represents network tokens, containing ip address, port and a SHA-256 hash of the public key.
    
    Usage examples:
      - Generating a token:

        >>> example_keydigest = "abcdefghijklmnopqrstuvwxyz012345"
        >>> token = str(NetworkToken(example_keydigest, '127.0.0.1', 63))
        >>> token
        'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXowMTIzNDV/AAABAD8A'

      - Parsing the generated token:

        >>> parsed_token = NetworkToken(token=token)
        >>> parsed_token
        NetworkToken('abcdefghijklmnopqrstuvwxyz012345', '127.0.0.1', 63)

    @ivar keyhash: SHA-256 hash of the public key
    @ivar ip_addr: dot-notation of the IP-address
    @ivar port: port used
    @type keyhash: bytes
    @type ip_addr: str
    @type port: int
    """
    def __init__(self, keyhash=None, ip_addr=None, port=0, token=None):
        """
        Initialize the class, either from presupplied values or from parsed token.
        @keyword keyhash: SHA-256 hash of the public key
        @keyword ip_addr: dot-notation of the IP-address to use
        @keyword port: port to use
        @keyword token: parse this token if none of the other parameters is specified
        @type token: str
        @type keyhash: bytes
        @type ip_addr: str
        @type port: int
        @raise ValueError: the keyhash or the token specified is not of the correct length, or not enough arguments are specified
        """
        if not keyhash is None and not ip_addr is None and not port == 0:
            if len(keyhash) != 32: raise ValueError("Invalid key hash length")
            self.keyhash = keyhash
            self.ip_addr = ip_addr
            self.port    = port
        elif not token is None:
            tokendata = b64decode(token)
            if len(tokendata) != 39:
                raise ValueError("Invalid token specified")
            self.keyhash = tokendata[:32]
            self.ip_addr = socket.inet_ntoa(tokendata[32:36])
            self.port,   = struct.unpack('>H', tokendata[36:38])
        else:
            raise ValueError("You need to specify either keyhash, ip_addr and port or token")
    def __repr__(self):
        """
        Generate a debug representation of this token,
        which can be used as a python expression to construct back exactly the same object.
        """
        return "NetworkToken(%s, %s, %s)" % (repr(self.keyhash), repr(self.ip_addr), repr(self.port))
    def __str__(self):
        """
        Generate the base64-encoded token string
        """
        ip_pack = socket.inet_aton(self.ip_addr)
        port_pack = struct.pack('>H', self.port)
        tokendata = self.keyhash + ip_pack + port_pack + '\0' # pad
        return b64encode(tokendata)


