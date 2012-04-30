#!/usr/bin/env python

import msgtypes
from entangled.kademlia.msgformat import MessageTranslator
import msgtypes

class TintangledDefaultFormat(MessageTranslator):
  """ The default on-the-wire message format for this library """
  def fromPrimitive(self, msgPrimitive):
    return msgtypes.fromPrimitive(msgPrimitive)

  def toPrimitive(self, message):
    return message.toPrimitives()
