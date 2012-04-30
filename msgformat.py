#!/usr/bin/env python

import msgtypes
from entangled.kademlia.msgformat import MessageTranslator
        
class TintangledDefaultFormat(MessageTranslator):
    """ The default on-the-wire message format for this library """
    typeRequest, typeResponse, typeError = range(3)
    headerType, headerMsgID, headerNodeID, headerCryptoChallengeX, header_public_key_n, headerPayload, headerArgs = range(7)
    
    def fromPrimitive(self, msgPrimitive):
        msgType = msgPrimitive[self.headerType]
        if msgType == self.typeRequest:
            msg = msgtypes.RequestMessage(msgPrimitive[self.headerNodeID], msgPrimitive[self.header_public_key_n], 
                msgPrimitive[self.headerCryptoChallengeX], msgPrimitive[self.headerPayload], msgPrimitive[self.headerArgs], msgPrimitive[self.headerMsgID])
        elif msgType == self.typeResponse:
            msg = msgtypes.ResponseMessage(msgPrimitive[self.headerMsgID], msgPrimitive[self.headerNodeID], msgPrimitive[self.header_public_key_n], 
                msgPrimitive[self.headerCryptoChallengeX], msgPrimitive[self.headerPayload])
        elif msgType == self.typeError:
            msg = msgtypes.ErrorMessage(msgPrimitive[self.headerMsgID], msgPrimitive[self.headerNodeID], msgPrimitive[self.header_public_key_n], 
                msgPrimitive[self.headerCryptoChallengeX], msgPrimitive[self.headerPayload], msgPrimitive[self.headerArgs])
        else:
            # Unknown message, no payload
            msg = msgtypes.Message(msgPrimitive[self.headerMsgID], msgPrimitive[self.headerNodeID],msgPrimitive[self.header_public_key_n], 
                msgPrimitive[self.headerCryptoChallengeX])
        return msg
    
    def toPrimitive(self, message):    
        msg = {self.headerMsgID:  message.id,
               self.headerNodeID: message.nodeID,
               self.headerCryptoChallengeX: message.crypto_challenge_x,
               self.header_public_key_n: message.public_key_n}
        if isinstance(message, msgtypes.RequestMessage):
            msg[self.headerType] = self.typeRequest
            msg[self.headerPayload] = message.request
            msg[self.headerArgs] = message.args
        elif isinstance(message, msgtypes.ErrorMessage):
            msg[self.headerType] = self.typeError
            msg[self.headerPayload] = message.exceptionType
            msg[self.headerArgs] = message.response
        elif isinstance(message, msgtypes.ResponseMessage):
            msg[self.headerType] = self.typeResponse
            msg[self.headerPayload] = message.response
        return msg
