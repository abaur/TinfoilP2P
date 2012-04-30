#!/usr/bin/env python

import msgtypes
from entangled.kademlia.msgformat import MessageTranslator
import msgtypes

class TintangledDefaultFormat(MessageTranslator):
  """ The default on-the-wire message format for this library """
  def fromPrimitive(self, msgPrimitive):
    msgType = msgPrimitive[0]
    if msgType == msgtypes.typeRequest:
        return msgtypes.RequestMessage(primitives = msgPrimitive)
    elif msgType == msgtypes.typeResponse:
        return msgtypes.ResponseMessage(primitives = msgPrimitive)
    elif msgType == msgtypes.typeError:
        return msgtypes.ErrorMessage(primitives = msgPrimitive)
    else:
        # Unknown message, no payload
        return msgtypes.Message(primitives = msgPrimitive)

  def toPrimitive(self, message):
    return message.toPrimitives()
