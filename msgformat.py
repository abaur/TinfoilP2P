#!/usr/bin/env python

import msgtypes
from entangled.kademlia.msgformat import MessageTranslator
import Crypto
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
    headerPublicKeyN,
    headerPublicKeyE,
    headerSignedValue, 
    headerPayload, 
    headerArgs
  ) = range(9)
  

  def fromPrimitive(self, msgPrimitive):
    
    msgType = msgPrimitive[self.headerType]

    rsaKey = Crypto.PublicKey.RSA.construct((
        msgPrimitive[self.headerPublicKeyN], 
        long(msgPrimitive[self.headerPublicKeyE])))

    if msgType == self.typeRequest:
      msg = msgtypes.RequestMessage(nodeID = msgPrimitive[self.headerNodeID],
        method = msgPrimitive[self.headerPayload], 
        methodArgs = [str(arg).decode("hex") for arg in msgPrimitive[self.headerArgs]],
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
      self.headerPublicKeyN: message.rsaKey.n,
      self.headerPublicKeyE: message.rsaKey.e,
      self.headerSignedValue: message.signedValue}
    if isinstance(message, msgtypes.RequestMessage):
      msg[self.headerType] = self.typeRequest
      msg[self.headerPayload] = message.request
      msg[self.headerArgs] = [str(arg).encode("hex") for arg in message.args]
    elif isinstance(message, msgtypes.ErrorMessage):
      msg[self.headerType] = self.typeError
      msg[self.headerPayload] = message.exceptionType
      msg[self.headerArgs] = message.response
    elif isinstance(message, msgtypes.ResponseMessage):
      msg[self.headerType] = self.typeResponse
      msg[self.headerPayload] = message.response
    return msg