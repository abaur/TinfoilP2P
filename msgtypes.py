#!/usr/bin/env python
#
# This library is free software, distributed under the terms of
# the GNU Lesser General Public License Version 3, or any later version.
# See the COPYING file included in this archive
#
# The docstrings in this module contain epytext markup; API documentation
# may be created by processing this file with epydoc: http://epydoc.sf.net

import util

class Message(object):
    """ Base class for messages - all "unknown" messages use this class """
    def __init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX, 
            signedValue = None):
        self.id = rpcID
        self.nodeID = nodeID
        self.rsaKey = rsaKey
        self.cryptoChallengeX = cryptoChallengeX
        self.signedValue = signedValue

    def stringToSign(self):
        return "%s" % (self.id)

class RequestMessage(Message):
    """ Message containing an RPC request """
    def __init__(self, nodeID, method, methodArgs, rsaKey, 
        cryptoChallengeX, rpcID=None, signedValue = None):
        if rpcID == None:
            rpcID = util.generateRandomString(160)
        Message.__init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX, 
                signedValue)
        self.request = method
        self.args = methodArgs
    
    def stringToSign(self):
        print "args: %s" % self.args
        return "%s%s%s" % (self.request, 
                [arg.encode("hex") for arg in self.args],
                Message.stringToSign(self))

class ResponseMessage(Message):
    """ Message containing the result from a successful RPC request """
    def __init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX, 
            response, signedValue = None):
        Message.__init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX, 
                signedValue)
        self.response = response

    def stringToSign(self):
        return "%s%s" % (self.response.encode("hex"), 
                Message.stringToSign(self))

class ErrorMessage(ResponseMessage):
    """ Message containing the error from an unsuccessful RPC request """
    def __init__(self, rpcID, nodeID, rsaKey, cryptoChallengeX, 
        exceptionType, errorMessage, signedValue = None):
        ResponseMessage.__init__(self, rpcID, nodeID, rsaKey, 
            cryptoChallengeX, errorMessage, signedValue)
        if isinstance(exceptionType, type):
            self.exceptionType = '%s.%s' % (exceptionType.__module__, 
                exceptionType.__name__)
        else:
            self.exceptionType = exceptionType
    
    def stringToSign(self):
        return "%s%s" % (self.exceptionType, 
                ResponseMessage.stringToSign(self))