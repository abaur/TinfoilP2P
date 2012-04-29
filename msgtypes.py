#!/usr/bin/env python
#
# This library is free software, distributed under the terms of
# the GNU Lesser General Public License Version 3, or any later version.
# See the COPYING file included in this archive
#
# The docstrings in this module contain epytext markup; API documentation
# may be created by processing this file with epydoc: http://epydoc.sf.net

import hashlib
import random

class Message(object):
    """ Base class for messages - all "unknown" messages use this class """
    def __init__(self, rpcID, nodeID, public_key_n, crypto_challenge_x):
        self.id = rpcID
        self.nodeID = nodeID
        self.public_key_n = public_key_n
        self.crypto_challenge_x = crypto_challenge_x


class RequestMessage(Message):
    """ Message containing an RPC request """
    def __init__(self, nodeID, method, methodArgs, public_key_n, crypto_challenge_x, rpcID=None):
        if rpcID == None:
            hash = hashlib.sha1()
            hash.update(str(random.getrandbits(255)))  
            rpcID = hash.digest()
        Message.__init__(self, rpcID, nodeID, public_key_n, crypto_challenge_x)
        self.request = method
        self.args = methodArgs


class ResponseMessage(Message):
    """ Message containing the result from a successful RPC request """
    def __init__(self, rpcID, nodeID, public_key_n, crypto_challenge_x, response):
        Message.__init__(self, rpcID, nodeID, public_key_n, crypto_challenge_x)
        self.response = response


class ErrorMessage(ResponseMessage):
    """ Message containing the error from an unsuccessful RPC request """
    def __init__(self, rpcID, nodeID, public_key_n, crypto_challenge_x, exceptionType, errorMessage):
        ResponseMessage.__init__(self, rpcID, nodeID, public_key_n, crypto_challenge_x, errorMessage)
        if isinstance(exceptionType, type):
            self.exceptionType = '%s.%s' % (exceptionType.__module__, exceptionType.__name__)
        else:
            self.exceptionType = exceptionType
