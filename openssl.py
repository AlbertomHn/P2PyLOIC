"""
Contains all OpenSSL-related stuff.
This module wraps the openssl crypto library in python using ctypes.

@var DSA_SIGNATURE_LENGTH: the length of dsa signatures
@type DSA_SIGNATURE_LENGTH: int
@var DSA_DIGEST_ACCEPT: the amount of digest the OpenSSL functions DSA_sign and DSA_verify can take.
                        before OpenSSL 1.0, they only take 160 bits, designed for use with SHA-1,
                        we're using sha-224, so we have to truncate it by 8 bytes.
@type DSA_DIGEST_ACCEPT: int

@var openssl: this contains the module handle for the crypto lib loaded by ctypes
@type openssl: ctypes.cdll

"""

import ctypes as ct
from ctypes.util import find_library
from hashlib import sha224

DSA_SIGNATURE_LENGTH = 48
DSA_DIGEST_ACCEPT = 20 # DSA_sign and DSA_verify, before openssl 1.0, take digest lengths of 20 bytes

class OpenSSLError(Exception):
    """
    The base class for errors regarding the OpenSSL library.
    All other errors in this module derive from this.
    """
    pass
class OpenSSLNotFound(OpenSSLError):
    """
    This exception is raised when ctypes can't find the openssl crypto library
    """
    def __init__(self):
        OpenSSLError.__init__(self, "OpenSSL crypto not found")
class OpenSSLRuntimeError(OpenSSLError):
    """
    This exception is raised when any openssl function call returns an error code.
    The init method will load the openssl crypto strings, and set the error value
    to the error string retrieved from openssl.
    """
    def __init__(self, method=None):
        """
        Find the actual error and construct the error string.
        @keyword method: the function that returned the error
        @type    method: str
        """
        if method == None:
            method = "call"
        openssl.ERR_load_crypto_strings()
        OpenSSLError.__init__(self, 
                "OpenSSL function %s returned error: %s" % 
                (method, ct.c_char_p(openssl.ERR_error_string(openssl.ERR_get_error(), 0)).value))
        openssl.ERR_free_strings()

def _findOpenSSL():
    """
    Use ctypes.util.find_library to find the crypto library.
    @precondition: the system actually has a library called crypto
    @raise OpenSSLNotFound: If ctypes couldn't find a library named crypto
    @postcondition: C{openssl} contains the imported module
    """
    name = find_library("crypto")
    if name is None: raise OpenSSLNotFound()
    return ct.cdll.LoadLibrary(name)
openssl = _findOpenSSL()


class DSA(object):
    """
    Represents DSA public/private keys. This class is basically a wrapper of the
    OpenSSL DSA struct.
    
    Examples:
      - Generating a key, and using it to sign a message:

            >>> dsa = DSA(generate=True)
            >>> message = "Hello, World! I'm a message"
            >>> signature = dsa.sign(message)

      - Verifying this message:

            >>> dsa.verify(message, signature)
            True
            >>> dsa.verify("Another message", signature)
            False

      - Printing the key to the user in base64:

            >>> import base64
            >>> print "===public key==="
            >>> print base64.b64encode(dsa.get_pubkey())
            >>> print "===private key==="
            >>> print base64.b64encode(dsa.get_privkey())

    @ivar _dsa: A pointer to the DSA object
    @type _dsa: DSA* (int)
       

    """
    def __init__(self, dsaptr=0, pubkey=None, privkey=None, generate=False):
        """
        Initialize a DSA class from int pointer, public key, private key, or generate one.
        
        @keyword dsaptr: this int pointer(already existing DSA*) is used to initialize the class
        @type    dsaptr: DSA* (int)
        @keyword pubkey: if dsaptr and privkey are not given, this is used to initialize the class
        @type    pubkey: bytes
        @keyword privkey: if dsaptr isn't given, this is used to initialize the class
        @type    privkey: bytes
        @keyword generate: if none of the other keywords are given, generate a new key if this is set to True
        @type    generate: bool
        
        @raise OpenSSLRuntimeError: if any of the OpenSSL functions called returns an error code,
                                    this is raised with more details on the error
        @raise ValueError: if none of the arguments are given, a ValueError is raised
        """
        if dsaptr != 0:
            pass
        elif not privkey is None: # load from a private key
            buff = ct.pointer(ct.create_string_buffer(privkey))
            dsaptr = openssl.d2i_DSAPrivateKey(0, ct.byref(buff), len(privkey));
            if dsaptr == 0: raise OpenSSLRuntimeError("d2i_DSAPrivateKey")
        elif not pubkey is None:    # load from a public key
            buff = ct.pointer(ct.create_string_buffer(pubkey))
            dsaptr = openssl.d2i_DSA_PUBKEY(0, ct.byref(buff), len(pubkey));
            if dsaptr == 0: raise OpenSSLRuntimeError("d2i_DSA_PUBKEY")
        elif generate:
            dsaptr = openssl.DSA_generate_parameters(1024, 0, 0, 0, 0, 0, 0)
            if dsaptr == 0:                           raise OpenSSLRuntimeError("DSA_generate_parameters")
            if openssl.DSA_generate_key(dsaptr) == 0: raise OpenSSLRuntimeError("DSA_generate_key")
        elif dsaptr == 0: 
            raise ValueError("can't pull DSA keys out of thin air")
        self._dsa = dsaptr
    def __del__(self):
        """
        Deconstructor for calling DSA_free
        """
        openssl.DSA_free(self._dsa)
    def get_pubkey(self):
        """
        Decode the public key from the object
        
        @return: the decoded public key
        @rtype: bytes
        
        @raise OpenSSLRuntimeError: if the OpenSSL function i2d_DSA_PUBKEY returns an error code,
                                    an OpenSSLRuntimeError is raised
        @see: U{the man page of i2d_DSA_PUBKEY <http://linux.die.net/man/3/i2d_dsapublickey>}
        """
        i2dout = ct.POINTER(ct.c_char)()
        i2dlen = openssl.i2d_DSA_PUBKEY(self._dsa, ct.byref(i2dout))
        if i2dlen < 1: raise OpenSSLRuntimeError("i2d_DSA_PUBKEY")
        pubkey = i2dout[:i2dlen]
        openssl.free(i2dout)
        return pubkey
    def get_privkey(self):
        """
        Decode the private key from the object
        
        @return: the decoded private key
        @rtype: bytes
        
        @raise OpenSSLRuntimeError: if the OpenSSL function i2d_DSAPrivateKey returns an error code,
                                    an OpenSSLRuntimeError is raised
        @see: U{the man page of i2d_DSAPrivateKey <http://linux.die.net/man/3/i2d_dsapublickey>}
        """
        i2dout = ct.POINTER(ct.c_char)()
        i2dlen = openssl.i2d_DSAPrivateKey(self._dsa, ct.byref(i2dout))
        if i2dlen < 1: raise OpenSSLRuntimeError("i2d_DSA_PUBKEY failed")
        privkey = i2dout[:i2dlen]
        openssl.free(i2dout)
        return privkey
    def sign(self, message):
        """
        Sign the message contained in C{message} with this DSA key
        
        @param message: the message that needs to be signed
        @type  message: str
        @return: the message signature
        @rtype: bytes
        
        @raise OpenSSLRuntimeError: if the OpenSSL function DSA_sign returns an error code,
                                    an OpenSSLRuntimeError is raised
        
        @precondition: the private key is known
        @bug: the program will segfault if the private key isn't known
        @see: U{the man page of DSA_sign <http://linux.die.net/man/3/dsa_sign_setup>}
        """
        signature = ct.create_string_buffer(DSA_SIGNATURE_LENGTH)
        rc = openssl.DSA_sign(0
                            , ct.byref(ct.create_string_buffer(sha224(message).digest()[:DSA_DIGEST_ACCEPT], DSA_DIGEST_ACCEPT))
                            , DSA_DIGEST_ACCEPT, signature
                            , ct.byref(ct.c_uint(DSA_SIGNATURE_LENGTH)), self._dsa)
        if rc != 1: raise OpenSSLRuntimeError("DSA_sign")
        return ''.join(signature)
    def verify(self, message, signature):
        """
        Verify if the signature contained in C{signature} was signed for the message C{message} with this public key
        
        @param message: the message that was signed
        @type  message: str
        @param signature: signature to be verified
        @type  signature: bytes
        @return: True if the signature was signed for this message with this key, False if not
        @rtype: bool
        
        @raise OpenSSLRuntimeError: if the OpenSSL function DSA_verify returns an error code,
                                    an OpenSSLRuntimeError is raised
        
        @see: U{the man page of DSA_verify <http://linux.die.net/man/3/dsa_sign_setup>}
        """
        rc = openssl.DSA_verify(0
                            , ct.byref(ct.create_string_buffer(sha224(message).digest()[:DSA_DIGEST_ACCEPT], DSA_DIGEST_ACCEPT))
                            , DSA_DIGEST_ACCEPT, ct.byref(ct.create_string_buffer(signature))
                            , DSA_SIGNATURE_LENGTH, self._dsa)
        if rc == -1: raise OpenSSLRuntimeError("DSA_verify")
        return rc == 1

from base64 import b64encode
if __name__ == '__main__':
    print "generating key"
    dsa_orig = DSA(generate=True)
    orig_pubkey = dsa_orig.get_pubkey()
    dsa_privateonly = DSA(privkey=dsa_orig.get_privkey())
    dsa_publiconly  = DSA(pubkey=dsa_orig.get_pubkey())
    dsa_privatepubkey = dsa_privateonly.get_pubkey()
    if orig_pubkey != dsa_privatepubkey:
        print "ERROR: PUBLIC KEYS ON RELOADED PRIVATE KEYS DON'T MATCH"
    message = "Hello, World!"
    signature = dsa_privateonly.sign(message)
    print "verifying signature:", dsa_publiconly.verify(message, signature)
    print "verifying signature on other message:", dsa_publiconly.verify("Another message", signature)
    

