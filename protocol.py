#!/usr/bin/env python
# coding: UTF-8


from entangled.kademlia.protocol import KademliaProtocol
from twisted.internet import protocol, defer
from twisted.python import failure
import twisted.internet.reactor
import util, time
import constants

from entangled.kademlia import encoding
import msgtypes
import msgformat
from entangled.kademlia.contact import Contact
import Crypto.Hash.SHA

reactor = twisted.internet.reactor

class TintangledProtocol(KademliaProtocol):
  def __init__(self, node, msgEncoder = encoding.Bencode(), 
    msgTranslator = msgformat.TintangledDefaultFormat()):
        KademliaProtocol.__init__(self,node, msgEncoder, msgTranslator)

  def _verifyID(self, nodeID, x):
    '''Verifies if a user's ID has been generated using the '''
    p1 = util.hsh2int(Crypto.Hash.SHA.new(nodeID))
    p2 = util.hsh2int(Crypto.Hash.SHA.new(
        util.int2bin((util.bin2int(nodeID) ^ x))))
    # check preceeding c_i bits in P1 and P2 using sharesXPrefices.
    return (
        util.hasNZeroBitPrefix(p1, constants.CRYPTO_CHALLENGE_C1) and
        util.hasNZeroBitPrefix(p2, constants.CRYPTO_CHALLENGE_C2))
   
  def _sendResponse(self, contact, rpcID, response):
    """ Send a RPC response to the specified contact"""
    msg = msgtypes.ResponseMessage(rpcID, self._node.id,
      self._node.rsaKey.publickey(), self._node.x, response)
    msg.signedValue = self._node._signMessage(msg.stringToSign())
    msgPrimitive = self._translator.toPrimitive(msg)
    encodedMsg = self._encoder.encode(msgPrimitive)
    self._send(encodedMsg, rpcID, (contact.address, contact.port))

  def _sendError(self, contact, rpcID, exceptionType, exceptionMessage):
    """ Send an RPC error message to the specified contact"""
    msg = msgtypes.ErrorMessage(rpcID, self._node.id,self._node.rsaKey.publickey(), 
      self._node.x, exceptionType, exceptionMessage)
    msg.signedValue = self._node._signMessage(msg.stringToSign())
    msgPrimitive = self._translator.toPrimitive(msg)
    encodedMsg = self._encoder.encode(msgPrimitive)
    self._send(encodedMsg, rpcID, (contact.address, contact.port))
  
  def sendRPC(self, contact, method, args, rawResponse=False):
    """ Sends an RPC to the specified contact

    @param contact: The contact (remote node) to send the RPC to
    @type contact: kademlia.contacts.Contact
    @param method: The name of remote method to invoke
    @type method: str
    @param args: A list of (non-keyword) arguments to pass to the remote 
      method, in the correct order
    @type args: tuple
    @param rawResponse: If this is set to C{True}, the caller of this RPC
                            will receive a tuple containing the actual response
                            message object and the originating address tuple as
                            a result; in other words, it will not be
                            interpreted by this class. Unless something special
                            needs to be done with the metadata associated with
                            the message, this should remain C{False}.
    @type rawResponse: bool

    @return: This immediately returns a deferred object, which will return
                 the result of the RPC call, or raise the relevant exception
                 if the remote node raised one. If C{rawResponse} is set to
                 C{True}, however, it will always return the actual response
                 message (which may be a C{ResponseMessage} or an
                 C{ErrorMessage}).
    @rtype: twisted.internet.defer.Deferred
        """
    msg = msgtypes.RequestMessage(nodeID = self._node.id, method = method,
        methodArgs = args, rsaKey = self._node.rsaKey.publickey(), 
        cryptoChallengeX = self._node.x)
    msg.signedValue = self._node._signMessage(msg.stringToSign())

    msgPrimitive = self._translator.toPrimitive(msg)
    encodedMsg = self._encoder.encode(msgPrimitive)

    df = defer.Deferred()
    if rawResponse:
      df._rpcRawResponse = True

    # Set the RPC timeout timer
    timeoutCall = reactor.callLater(constants.rpcTimeout, 
      self._msgTimeout, msg.id) #IGNORE:E1101
    # Transmit the data
    self._send(encodedMsg, msg.id, (contact.address, contact.port))
    self._sentMessages[msg.id] = (contact.id, df, timeoutCall)
    return df

  def datagramReceived(self, datagram, address):
    """ Handles and parses incoming RPC messages (and responses)

    @note: This is automatically called by Twisted when the protocol
     receives a UDP datagram
    """
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
    remoteContact.rsaKey = message.rsaKey
    #print 'Receied RPC from: %s to: %s' % (remoteContact.port, self._node.port)
    if not self._verifyID(remoteContact.id, message.cryptoChallengeX):
      print 'Id not verified - rejects RPC'
      return

    if not self._node._verifyMessage(message.stringToSign(), message.signedValue, message.rsaKey):
      print '##### - - - - - Did not verify message - rejects RPC: %s' % message
      return
    # As written in s/kademlia the message is signed and actively valid, 
    #  if the sender address is valid and comes from a RPC response.
    # Actively valid sender addresses are immediately added to their 
    #  corresponding bucket.
    # Valid sender addresses are only added to a bucket if the nodeId 
    #  preffix differs in an appropriate amount of bits.
    if isinstance(message, msgtypes.RequestMessage):
      # This is an RPC method request
      if util.sharesXBitPrefix(remoteContact.id, self._node.id, 
        constants.NODE_ID_PREFIX_DIFFERS_BITS) == False:
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