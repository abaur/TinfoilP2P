#!/usr/bin/env python
# coding: UTF-8


import entangled
import entangled.kademlia.constants
import entangled.kademlia.contact
import entangled.kademlia.protocol
import twisted.internet.reactor
import twisted.internet.threads
import twisted.internet.defer

import protocol
import util

import binascii
import constants
import Crypto.Hash.SHA
import hashlib
import random
import time


# Borrowed from kademlia - need it as a decorator below
def rpcmethod(func):
  func.rpcmethod = True
  return func

class TintangledNode(entangled.EntangledNode):

  def __init__(
      self, id = None, udpPort = 4000, dataStore = None, routingTable = None, 
      vanillaEntangled = False):
    """ Initializes a TintangledNode."""
    self.keyCache = {}
    self.rsaKey = None
    if vanillaEntangled:
      networkProtocol = entangled.kademlia.protocol.KademliaProtocol(self)
    else:
      networkProtocol = protocol.TintangledProtocol(self)
    if id == None:
      id = self._generateRandomID()

    entangled.EntangledNode.__init__(
        self, id, udpPort, dataStore, routingTable,
        # TODO(cskau): This protocol seems buggy.
        # It doesn't seem to store in the network - only locally at the orig node
        networkProtocol = networkProtocol)

  def _iterativeFind(self, key, startupShortlist=None, rpc='findNode'):
    """ The basic Kademlia iterative lookup operation (for nodes/values)

    This builds a list of k "closest" contacts through iterative use of
    the "FIND_NODE" RPC, or if C{findValue} is set to C{True}, using the
    "FIND_VALUE" RPC, in which case the value (if found) may be returned
    instead of a list of contacts

    @param key: the 160-bit key (i.e. the node or value ID) to search for
    @type key: str
    @param startupShortlist: A list of contacts to use as the starting
                 shortlist for this search; this is normally
                 only used when the node joins the network
    @type startupShortlist: list
    @param rpc: The name of the RPC to issue to remote nodes during the
          Kademlia lookup operation (e.g. this sets whether this
          algorithm should search for a data value (if
          rpc='findValue') or not. It can thus be used to perform
          other operations that piggy-back on the basic Kademlia
          lookup operation (Entangled's "delete" RPC, for instance).
    @type rpc: str

    @return: If C{findValue} is C{True}, the algorithm will stop as soon
         as a data value for C{key} is found, and return a dictionary
         containing the key and the found value. Otherwise, it will
         return a list of the k closest nodes to the specified key
    @rtype: twisted.internet.defer.Deferred
    """
    if rpc != 'findNode':
      findValue = True
    else:
      findValue = False
    shortlist = []
    if startupShortlist == None:
      shortlist = self._routingTable.findCloseNodes(
          key,
          entangled.kademlia.constants.alpha)
      if key != self.id:
        # Update the "last accessed" timestamp for the appropriate k-bucket
        self._routingTable.touchKBucket(key)
      if len(shortlist) == 0:
        # This node doesn't know of any other nodes
        fakeDf = twisted.internet.defer.Deferred()
        fakeDf.callback([])
        return fakeDf
    else:
      # This is used during the bootstrap process; node ID's are most probably fake
      shortlist = startupShortlist
    # List of active queries; len() indicates number of active probes
    # - using lists for these variables, because Python doesn't allow binding
    #  a new value to a name in an enclosing (non-global) scope
    activeProbes = []
    # List of contact IDs that have already been queried
    alreadyContacted = []
    # Probes that were active during the previous iteration
    # A list of found and known-to-be-active remote nodes
    activeContacts = []
    findValueResult = {}

    def nodeResponds(responseTuple):
      """ @type responseMsg: kademlia.msgtypes.ResponseMessage """
      # The "raw response" tuple contains the response message, and
      #  the originating address info

      responseMsg = responseTuple[0]

      originAddress = responseTuple[1] # tuple: (ip adress, udp port)
      # Make sure the responding node is valid, and abort the operation if it isn't
      if responseMsg.nodeID in activeContacts or responseMsg.nodeID == self.id:
        return responseMsg.nodeID

      # Mark this node as active
      if responseMsg.nodeID in shortlist:
        # Get the contact information from the shortlist...
        aContact = shortlist[shortlist.index(responseMsg.nodeID)]
      else:
        # If it's not in the shortlist; we probably used a fake ID to reach it
        # - reconstruct the contact, using the real node ID this time
        aContact = entangled.kademlia.contact.Contact(
            responseMsg.nodeID,
            originAddress[0],
            originAddress[1],
            self._protocol)
      activeContacts.append(aContact)
      # This makes sure "bootstrap"-nodes with "fake" IDs don't get queried twice
      if responseMsg.nodeID not in alreadyContacted:
        alreadyContacted.append(responseMsg.nodeID)
      # Now grow extend the (unverified) shortlist with the returned contacts
      result = responseMsg.response
      #TODO: some validation on the result (for guarding against attacks)
      # If we are looking for a value, first see if this result is the value
      # we are looking for before treating it as a list of contact triples
      if findValue == True and type(result) == dict:
        # We have found the value
        findValueResult[key] = result[key]
      else:
        if findValue == True:
          # We are looking for a value, and the remote node didn't have it
          # - mark it as the closest "empty" node, if it is
          if 'closestNodeNoValue' in findValueResult:
            if (
                self._routingTable.distance(key, responseMsg.nodeID) <
                self._routingTable.distance(key, activeContacts[0].id)):
              findValueResult['closestNodeNoValue'] = aContact
          else:
            findValueResult['closestNodeNoValue'] = aContact
        contactsGateheredFromNode = []
        #This node can't provide us with better results then return
        if result is not None:
          for contactTriple in result:
            if isinstance(contactTriple, (list, tuple)) and len(contactTriple) == 3:
              testContact = entangled.kademlia.contact.Contact(
                  contactTriple[0],
                  contactTriple[1],
                  contactTriple[2],
                  self._protocol)
              if testContact not in alreadyContacted:
                contactsGateheredFromNode.append(testContact)
          if len(contactsGateheredFromNode):
            contactsGateheredFromNode.sort(
                lambda firstContact, secondContact, targetKey=key:
                    cmp(
                        self._routingTable.distance(firstContact.id, targetKey),
                        self._routingTable.distance(secondContact.id, targetKey)))
            contactNode(contactsGateheredFromNode.pop(), contactsGateheredFromNode)
      return responseMsg.nodeID

    def nodeFailedToRespond(failure, otherNodesToContact):
      """ @type failure: twisted.python.failure.Failure """
      failure.trap(entangled.kademlia.protocol.TimeoutError)
      deadContactID = failure.getErrorMessage()
      if len(otherNodesToContact):
        contactNode(otherNodesToContact.pop(), otherNodesToContact)
      return deadContactID

    def cancelActiveProbe(contactID, nodeToRemove):
      """Cancels the specified probe of a node."""
      activeProbes.remove(nodeToRemove)

    def checkIfWeAreDone():
      """Check if we have found what we were looking for."""
      if len(activeProbes):
        # Schedule the next iteration if there are any active calls
        #  (Kademlia uses loose parallelism)
        twisted.internet.reactor.callLater(
            entangled.kademlia.constants.iterativeLookupDelay,
            checkIfWeAreDone) #IGNORE:E1101
      # Check for a quick contact response that made an update to the shortList
      elif key in findValueResult:
        #print '++++++++++++++ DONE (findValue found) +++++++++++++++\n\n'
        outerDf.callback(findValueResult)
      else:
        #print '++++++++++++++ DONE (logically) +++++++++++++\n\n'
        # If no probes were sent, there will not be any improvement, so we're done
        outerDf.callback(activeContacts)

    def contactNode(nodeToContact, candidateNodesToContact):
      """Contacts the specified node."""
      if nodeToContact.id not in alreadyContacted:
        activeProbes.append(nodeToContact.id)
        rpcMethod = getattr(nodeToContact, rpc)
        df = rpcMethod(key, rawResponse=True)
        df.addCallback(nodeResponds)
        df.addErrback(nodeFailedToRespond, candidateNodesToContact)
        df.addCallback(cancelActiveProbe, nodeToContact)
        alreadyContacted.append(nodeToContact.id)
        return True
      return False

    # Send parallel, asynchronous FIND_NODE RPCs to the shortlist of contacts
    def startIteration():
      """Starts contacting nodes."""
      contactedNow = 0
      shortlist.sort(lambda firstContact, secondContact, targetKey=key:
          cmp(
              self._routingTable.distance(firstContact.id, targetKey),
              self._routingTable.distance(secondContact.id, targetKey)))
      # Store the current shortList length before contacting other nodes
      while (contactedNow < entangled.kademlia.constants.alpha) and len(shortlist):
        contact = shortlist.pop()
        if contactNode(contact, shortlist):
          contactedNow += 1

      checkIfWeAreDone()

    outerDf = twisted.internet.defer.Deferred()
    # Start the iterations
    startIteration()
    return outerDf

  def _generateRandomID(self, complexityValue = 2):
    """Generates the NodeID by solving two cryptographic puzzles."""
    print('Generating a crypto ID...')
    # Solve the static cryptographic puzzle.
    rsaKey = None
    p = 0x1 # non-zero value
    pub = None

    randomStream = Crypto.Random.new().read
    while not util.hasNZeroBitPrefix(p, constants.CRYPTO_CHALLENGE_C1):
      rsaKey = Crypto.PublicKey.RSA.generate(constants.RSA_BITS, randomStream)
      pub = str(rsaKey.n) + str(rsaKey.e)
      p = util.hsh2int(Crypto.Hash.SHA.new(Crypto.Hash.SHA.new(pub).digest()))

    # created correct NodeID
    self.rsaKey = rsaKey
    nodeID = Crypto.Hash.SHA.new(pub)

    # Solve the dynamic cryptographic puzzle.
    p, x = 0x1, None

    while not util.hasNZeroBitPrefix(p, constants.CRYPTO_CHALLENGE_C2):
      x = util.bin2int(util.generateRandomString(constants.ID_LENGTH))
      # This is madness!
      p = util.hsh2int(
          Crypto.Hash.SHA.new(
              util.int2bin(
                  (util.hsh2int(nodeID) ^ x))))

    # Found a correct value of X and nodeID
    self.x = x
    return nodeID.digest()

  def getNameID(self, name):
    '''Calculate and return 160-bit ID for a given name.'''
    h = hashlib.sha1()
    h.update(name)
    return h.digest()

  def _signMessage(self, message):
    '''Signs the specified message using the node's private key.'''
    hashValue = Crypto.Hash.SHA.new(message).digest()
    return self.rsaKey.sign(hashValue, '') # Extra parameter not relevant for RSA.

  def _verifyMessage(self, message, signature, rsaKey = None):
    '''Verify a message based on the specified signature.'''
    if rsaKey is None:
      rsaKey = self.rsaKey
    hashValue = Crypto.Hash.SHA.new(message).digest()
    return rsaKey.verify(hashValue, signature)

  # -*- Logging Decorators -*-

  def addContact(self, contact):
    #print('I : %s adds: "%s"' % (self.port, contact.port))
    if contact.rsaKey is not None:
      self.keyCache[contact.id] = contact.rsaKey
    entangled.EntangledNode.addContact(self, contact)

  def publishData(self, name, data):
    #print('publishData: "%s":"%s"' % (name, data))
    entangled.EntangledNode.publishData(self, name, data)

  @rpcmethod
  def store(self, key, value, originalPublisherID=None, age=0, **kwargs):
    #print('store: "%s":"%s" (%s, %s)' % (key, value, originalPublisherID, age))
    entangled.EntangledNode.store(self, key, value, originalPublisherID, age, **kwargs)

# end-of-node.py
