#!/usr/bin/env python

import msgtypes
from entangled.kademlia.msgformat import MessageTranslator
import msgtypes

class TintangledDefaultFormat(MessageTranslator):
  """ The default on-the-wire message format for this library """
  def fromPrimitive(self, msgPrimitive):
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

  def toPrimitive(self, message):
    return message.toPrimitives()
