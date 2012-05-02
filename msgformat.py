#!/usr/bin/env python

import msgtypes
from entangled.kademlia.msgformat import MessageTranslator
import util
import Crypto
import pickle

class TintangledDefaultFormat(MessageTranslator):
  """ The default on-the-wire message format for this library """
  (
    typeRequest, 
    typeResponse, 
    typeError
  ) = range(3)
  
  (
    headerType, 
    headerMsgID, 
    headerNodeID, 
    headerCryptoChallengeX,
    headerPublicKey,
    headerSignedValue, 
    headerPayload, 
    headerArgs
  ) = range(8)
  
  def fromPrimitive(self, msgPrimitive):
    
    msgType = msgPrimitive[self.headerType]

    rsaKey = pickle.loads(msgPrimitive[self.headerPublicKey])

    if msgType == self.typeRequest:
      msg = msgtypes.RequestMessage(nodeID = msgPrimitive[self.headerNodeID],
        method = msgPrimitive[self.headerPayload], 
        methodArgs = pickle.loads(msgPrimitive[self.headerArgs]),
        rsaKey = rsaKey,
        cryptoChallengeX = msgPrimitive[self.headerCryptoChallengeX], 
        rpcID = msgPrimitive[self.headerMsgID],
        signedValue = msgPrimitive[self.headerSignedValue])
    elif msgType == self.typeResponse:
      msg = msgtypes.ResponseMessage(rpcID = msgPrimitive[self.headerMsgID], 
        nodeID = msgPrimitive[self.headerNodeID], 
        rsaKey = rsaKey, 
        cryptoChallengeX = msgPrimitive[self.headerCryptoChallengeX],
        response = msgPrimitive[self.headerPayload],
        signedValue = msgPrimitive[self.headerSignedValue])
    elif msgType == self.typeError:
      msg = msgtypes.ErrorMessage(msgPrimitive[self.headerMsgID], 
        msgPrimitive[self.headerNodeID], 
        rsaKey, 
        msgPrimitive[self.headerCryptoChallengeX], 
        msgPrimitive[self.headerPayload], 
        msgPrimitive[self.headerArgs],
        msgPrimitive[self.headerSignedValue])
    else:
      # Unknown message, no payload
      msg = msgtypes.Message(msgPrimitive[self.headerMsgID], 
        msgPrimitive[self.headerNodeID],
        rsaKey, 
        msgPrimitive[self.headerCryptoChallengeX],
        msgPrimitive[self.headerSignedValue])
    return msg

  def toPrimitive(self, message):    
    msg = {self.headerMsgID:  message.id,
      self.headerNodeID: message.nodeID,
      self.headerCryptoChallengeX: message.cryptoChallengeX,
      self.headerPublicKey: pickle.dumps(message.rsaKey),
      self.headerSignedValue: message.signedValue,}
    if isinstance(message, msgtypes.RequestMessage):
      msg[self.headerType] = self.typeRequest
      msg[self.headerPayload] = message.request
      msg[self.headerArgs] = pickle.dumps(message.args)
    elif isinstance(message, msgtypes.ErrorMessage):
      msg[self.headerType] = self.typeError
      msg[self.headerPayload] = message.exceptionType
      msg[self.headerArgs] = message.response
    elif isinstance(message, msgtypes.ResponseMessage):
      msg[self.headerType] = self.typeResponse
      msg[self.headerPayload] = message.response
    return msg