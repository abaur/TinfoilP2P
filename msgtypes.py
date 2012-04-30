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
import util
import constants
    
(
    typeRequest, 
    typeResponse, 
    typeError,
) = range(3)
  
(
    headerType,
    headerMsgID,
    headerNodeID, 
    headerCryptoChallengeX,
    headerPublicKeyN, 
    headerPayload, 
    headerArgs,
    headerNonce,
) = range(8)

def fromPrimitive(msgPrimitive):
    print msgPrimitive
    msgType = msgPrimitive[0]
    if msgType == typeRequest:
        return RequestMessage(primitives = msgPrimitive)
    elif msgType == typeResponse:
        return ResponseMessage(primitives = msgPrimitive)
    elif msgType == typeError:
        return ErrorMessage(primitives = msgPrimitive)
    else:
        # Unknown message, no payload
        return Message(primitives = msgPrimitive)

class Message(object):

    """ Base class for messages - all "unknown" messages use this class """
    def __init__(self, rpcID = None, nodeID = None, rsaKey = None, cryptoChallengeX = None, primitives = None):
        if primitives == None:
            self.id = rpcID
            self.nodeID = nodeID
            self.publicKeyN = rsaKey
            self.cryptoChallengeX = cryptoChallengeX
            self.nonce = util.generateRandomString(constants.NONCE_LENGTH)
        else:
            self.fromPrimitives(primitives)

    def fromPrimitives(self, primitives):
        self.id = primitives[headerMsgID]
        self.nodeID = primitives[headerNodeID]
        self.cryptoChallengeX = primitives[headerCryptoChallengeX]
        self.publicKeyN = primitives[headerPublicKeyN]
        self.nonce = primitives[headerNonce]

    def toPrimitives(self):
        msg = { headerMsgID:  self.id,
                headerNodeID: self.nodeID,
                headerCryptoChallengeX: self.cryptoChallengeX,
                headerPublicKeyN: self.publicKeyN,
                headerNonce: self.nonce}
        return msg

    def stringSignatureToSign(self):
        return "%s%s" % (self.nodeID, self.nonce)

class RequestMessage(Message):
    """ Message containing an RPC request """
    def __init__(self, nodeID = None, method = None, methodArgs = None, 
        rsaKey = None, cryptoChallengeX = None, rpcID=None, primitives = None):
        if rpcID == None:
            hash = hashlib.sha1()
            hash.update(str(random.getrandbits(255)))  
            rpcID = hash.digest()
        self.request = method
        self.args = methodArgs
        Message.__init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX)

    def stringSignatureToSign(self):
        return "" % (Message.stringSignatureToSign(), self.request, self.args)

    def fromPrimitives(primitives):
        Message.fromPrimitives(primitives)
        self.request = primitives[headerPayload]
        self.args = primitives[headerArgs]

    def toPrimitives(self):
        msg = Message.toPrimitives(self)
        msg[headerType] = typeRequest
        msg[headerPayload] = self.request
        msg[headerArgs] = self.args
        return msg
    

class ResponseMessage(Message):
    """ Message containing the result from a successful RPC request """
    def __init__(self, rpcID = None, nodeID = None, rsaKey = None, 
        cryptoChallengeX = None , response = None, primitives = None):
        self.response = response
        Message.__init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX)

    def stringSignatureToSign(self):
        return "" % (Message.stringSignatureToSign(), self.response)

    def fromPrimitives(self, primitives):
        Message.fromPrimitives(primitives)
        self.response = msg[headerPayload]

    def toPrimitives(self):
        msg = Message.toPrimitives()
        msg[headerType] = typeResponse
        msg[headerPayload] = self.response
        return msg


class ErrorMessage(ResponseMessage):
    """ Message containing the error from an unsuccessful RPC request """
    def __init__(self, rpcID = None, nodeID = None, rsaKey = None, cryptoChallengeX = None, 
        exceptionType = None, errorMessage = None, primitives = None):
        if isinstance(exceptionType, type):
            self.exceptionType = '%s.%s' % (exceptionType.__module__, 
                exceptionType.__name__)
        else:
            self.exceptionType = exceptionType
        ResponseMessage.__init__(self, rpcID, nodeID, publicKeyN, 
            cryptoChallengeX, errorMessage, primitives)

    def stringSignatureToSign(self):
        return "%s%s" % (Message.stringSignatureToSign(), self.exceptionType)

    def fromPrimitives(self, primitives):
        Message.fromPrimitives(primitives)
        self.exceptionType = primitives[headerPayload]
        self.errorMessage = primitives[headerArgs]        

    def toPrimitives(self):
        msg = Message.toPrimitives()
        msg[headerType] = typeError
        msg[headerPayload] = self.exceptionType
        msg[headerArgs] = self.errorMessage
        return msg