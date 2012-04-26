#!/usr/bin/env python
# coding: UTF-8


from entangled.kademlia.protocol import KademliaProtocol
from twisted.internet import protocol, defer
from twisted.python import failure
import twisted.internet.reactor
import util
from entangled.kademlia import constants
from entangled.kademlia import encoding
from entangled.kademlia import msgtypes
from entangled.kademlia import msgformat
from entangled.kademlia.contact import Contact


class TintangledProtocol(KademliaProtocol):
  """ Handles and parses incoming RPC messages (and responses)

  @note: This is automatically called by Twisted when the protocol
   receives a UDP datagram
  """
  def datagramReceived(self, datagram, address):
    if datagram[0] == '\x00' and datagram[25] == '\x00':
      totalPackets = (ord(datagram[1]) << 8) | ord(datagram[2])
      msgID = datagram[5:25]
      seqNumber = (ord(datagram[3]) << 8) | ord(datagram[4])
      if msgID not in self._partialMessages:
        self._partialMessages[msgID] = {}
      self._partialMessages[msgID][seqNumber] = datagram[26:]
      if len(self._partialMessages[msgID]) == totalPackets:
        keys = self._partialMessages[msgID].keys()
        keys.sort()
        data = ''
        for key in keys:
          data += self._partialMessages[msgID][key]
          datagram = data
        del self._partialMessages[msgID]
      else:
        return
    try:
      msgPrimitive = self._encoder.decode(datagram)
    except encoding.DecodeError:
      # We received some rubbish here
      return


    message = self._translator.fromPrimitive(msgPrimitive)
    remoteContact = Contact(message.nodeID, address[0], address[1], self)
    # As written in s/kademlia the message is signed and actively valid, 
    #  if the sender address is valid and comes from a RPC response.
    # Actively valid sender addresses are immediately added to their 
    #  corresponding bucket.
    # Valid sender addresses are only added to a bucket if the nodeId 
    #  preffix differs in an appropriate amount of bits.
    if isinstance(message, msgtypes.RequestMessage):
      # This is an RPC method request
      # TODO(cskau): Why 33 bits? Also, this is a constant!
      if util.sharesXBitPrefix(remoteContact.id, self._node.id, 33) == False:
        self._node.addContact(remoteContact)
      self._handleRPC(remoteContact, message.id, message.request, message.args)
    elif isinstance(message, msgtypes.ResponseMessage):
      # Find the message that triggered this response
      # Refresh the remote node's details in the local node's k-buckets
      self._node.addContact(remoteContact)

      if self._sentMessages.has_key(message.id):
          # Cancel timeout timer for this RPC
          df, timeoutCall = self._sentMessages[message.id][1:3]
          timeoutCall.cancel()
          del self._sentMessages[message.id]

          if hasattr(df, '_rpcRawResponse'):
            # The RPC requested that the raw response message and 
            #  originating address be returned; do not interpret it.
            df.callback((message, address))
          elif isinstance(message, msgtypes.ErrorMessage):
            # The RPC request raised a remote exception; raise it locally
            if message.exceptionType.startswith('exceptions.'):
              exceptionClassName = message.exceptionType[11:]
            else:
              localModuleHierarchy = self.__module__.split('.')
              remoteHierarchy = message.exceptionType.split('.')
              #strip the remote hierarchy
              while remoteHierarchy[0] == localModuleHierarchy[0]:
                remoteHierarchy.pop(0)
                localModuleHierarchy.pop(0)
                exceptionClassName = '.'.join(remoteHierarchy)
                remoteException = None
                try:
                  # TODO(cskau): "exec"? hmm...
                  exec 'remoteException = %s("%s")' % (
                      exceptionClassName, message.response)
                except Exception:
                  # We could not recreate the exception; create a generic one
                  remoteException = Exception(message.response)
                  df.errback(remoteException)
          else:
            # We got a result from the RPC
            df.callback(message.response)
      else:
        # If the original message isn't found, it must have timed out
        #TODO: we should probably do something with this...
        pass
