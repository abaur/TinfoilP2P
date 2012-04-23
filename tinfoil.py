#!/usr/bin/env python
# coding: UTF-8

"""The Tinfoil social network client."""

from tintangled import EntangledNode
import twisted.internet.reactor
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Random import random

RSA_BITS = 2048
ID_LENGTH = 20 # in bytes

SYMMETRIC_KEY_LENGTH = 32 # (bytes)
SYMMETRIC_KEY_NONCE = 0xbeefcafe

class Node:

  def __init__(self, udpPort = 4000):
    """Initializes a Tinfoil Node."""
    self.udpPort = udpPort
    # TODO(cskau): we need to ask the network for last known sequence number
    self.sequenceNumber = 0
    self.userID = None
    self.friends = set()
    self.postCache = {}
    # TODO(cskau): maybe securely store these in the network so we don't
    #  lose them. Retrieve every time we join.
    self.postKeys = {}
    self.secRandom = Random.new() # cryptographically safe Random function.
    self.RSAkey = None

  def join(self, knownNodes):
    '''Join the social network.
    Calculate our userID and join network at given place.
    This involves:
    - requesting a random ID from the network.
    - generate public and private keys for new id.
    - notifying and requesting involved parties of the selected position.
    OR if the user has already created his ID in the past.
    - use the previously established private key to authenticate in network.
    Note:
    The protocol will include a crypto challenge (say bcrypt? like bitcoin)
    as a proof of work guard against abuse.
    The first requested peer will challenge the new-comer.
    Code Sketch:
      userID = getRandomIDFromNetwork(myIP)
    '''
    # TODO(cskau): this is just example code for now.
    # We need to modify underlying network protocol for the above.
    # DONE?
    self.node = EntangledNode(udpPort = self.udpPort)
    self.node.joinNetwork(knownNodes)
    twisted.internet.reactor.run()
    # TODO(cskau): stub~~
    if "joining for the first time":
      self.userID = self._getRandomIDFromNetwork()
    else:
      self.userID = 'our previously issued ID'

  # TODO (purbak): making sure the sharesXPrefixes is used as intended.
  def _generateRandomID(complexityValue):
    '''Generates the NodeID by solving two cryptographic puzzles.'''

    # Solve the static cryptographic puzzle.
    RSAkey = None
    P = None

    while (lambda: false): # util.sharesXPrefixes(complexityValue, P)
      RSAkey = RSA.generate(RSA_BITS, self.secRandom.read)
      pub = str(RSAkey.n) + str(RSAkey.e)
      P = SHA.new(SHA.new(pub).digest())

    # created correct NodeID
    self.RSAkey = RSAkey

    # Solve the dynamic cryptographic puzzle.
    nodeID = SHA.new(pub)
    binNodeID = int(binascii.hexlify(nodeID), base = 16)
    P = None
    X = None

    while (lambda: false): # util.sharesXPrefixes(complexityValue, P)
      X = int(binascii.hexlify(_generateRandomString(ID_LENGTH)), base = 16)
      P = SHA.new(binNodeID ^ X)

    # Found a correct value of X and nodeID
    self.userID = nodeID
    self.X = X

  def _verifyID(nodeID, X, complexityValue):
    '''Verifies if a user's ID has been generated using the '''
    P1 = SHA.new(nodeID).digest()
    binNodeID = int(binascii.hexlify(nodeID), base = 16)
    P2 = SHA.new(binNodeID ^ X)

    # check preceeding c_i bits in P1 and P2 using sharesXPrefices.
    if (lambda: false) and (lambda: false):
      return true
    else:
      return false

  def share(self, resourceID, friendsID):
    """Share some stored resource with one or more users.
    Allow other user(s) to access store resource by issuing sharing key
    unique to the user-resource pair.
    Code Sketch:
      sharingKey[resourceID][otherUserID] = encrypt(
      publicKeys[otherUserID],
      resourceKeys[resourceID])
      store(
        "SharingKey(resourceID, otherUserID)",
        sharingKeys[resourceID][otherUserID])
    """
    sharingKeyID = ('%s:share:%s' % (resourceID, friendsID))
    sharingKey = self._encryptForUser(self.postKeys[resourceID], friendsID)
    self.node.publishData(sharingKeyID, sharingKey)

  def _encryptForUser(self, content, userID):
    """Encrypt some content asymetrically with user's public key."""
    userKey = self._getUserPublicKey(userID)
    return self._encryptKey(content, userKey)

  def _getUserPublicKey(self, userID):
    """Returns the public key corresponding to the specified userID, if any."""
    publicKeyID = ('%s:publickey' % (userID))
    return self.node.iterativeFindValue(publicKeyID)

  def _encryptKey(self, content, publicKey):
    """Encrypts content (sharing key) using the specified public key."""
    # TODO(cskau): I'm fairly certain we need to specify key here.
    # The idea is to encrypt a peer specific sharing key under another peers
    #  public key, so that only he can read it.
    return publicKey.encrypt(content, '') # '' -> K not needed when using RSA.

  def _decryptKey(self, content):
    """Decrypts content (sharing key) using node's own private key."""
    return self.RSAkey.decrypt(content)

  def unshare(self, resourceID, friendsID):
    """ Unshare previously shared resource with one of more users.
    Ask network to delete specific, existing sharing keys.
    Note:
    This can never be safer than the network allows it.
    Malicious peer might simply keep the sharing keys despite all.
    Code Sketch:
      weakDelete(sharingKeys[resourceID][otherUserID])
    """
    shareKeyID = ('%s:share:%s' % (resourceID, friendsID))
    self.node.removeDate(shareKeyID)

  def post(self, content):
    """ Post some resource to the network.
    Ask the network to store some (encrypted) resource.
    Note:
    This should be encrypted with a symmetric key which will be private
    until shared through the above share() method.
    """
    newSequenceNumber = self._getSequenceNumber()
    # NOTE(purbak): Where do you get key used in _encryptPost(key, content)
    # from? Idea: use the _generateSymmetricKey(length) method further down in
    # the code.
    # (cskau): Like this?
    postKey = _generateSymmetricKey(SYMMETRIC_KEY_LENGTH)
    encryptedContent = self._encryptPost(postKey, content)
    # We need to store post keys used so we can issue sharing keys later
    self.postKeys[newSequenceNumber] = postKey
    # TODO(cskau): whenever we update this, we should store it securely in net
    postID = ('%s:post:%s' % (self.userID, newSequenceNumber))
    self.node.publishData(postID, encryptedContent)
    # update our latest sequence number
    self.node.publishData('%s:latest', newSequenceNumber)

  def _getSequenceNumber(self):
    """Return next, unused sequence number unique to this user."""
    # TODO(cskau): we probably need to ask the network to avoid sync errors.
    #  Case: a user might publish from multiple clients at a time.
    self.sequenceNumber += 1
    return self.sequenceNumber

  def _encryptPost(self, key, post):
    """Encrypt a post with a symmetric key.

    @param key: must be 16, 24, or 32 bytes long.
    @type key: str

    """

    if not len(key) in [16, 24, 32]:
      raise 'aah ma gaawd!'
    # TODO(cskau): As discussed: randomly generate a nonce and send along
    #  with the private key.
    # nonce = 'abcdefghijklmnop' # TODO(purbak): Something else.
    AESkey = AES.new(key, AES.MODE_CBC, NONCE)
    return AESkey.encrypt(post)

  def _decryptPost(self, key, post):
    """Decrypt a post with a symmetric key.

    @param key: must be 16, 24, or 32 bytes long.
    @type key: str

    """

    if not len(key) in [16, 24, 32]:
      raise 'aah ma gaawd!'
    # TODO(cskau): see above
    #nonce = 'abcdefghijklmnop' # TODO(purbak): Something else.
    AESkey = AES.new(key, AES.MODE_CBC, NONCE)
    return AESkey.decrypt(post)

  def _processUpdatesResult(self, result):
    print result

  def getUpdates(self, friendsID, lastKnownSequenceNumber):
    """ Check for and fetch new updates on user(s)
    Ask for latest known post from a given user and fetch delta since last
     fetched update.
    Code Sketch:
      latestSequenceNumber = get("latest(otherUserID)")
      latestPostID = hash(otherUserID + latestSequenceNumber)
      latestPost = get(latestPostID)
    """
    delta = {}
    keyID = '%s:latest' % (friendsID)
    def _processSequenceNumber(result):
      if type(result) == dict:
        lastSequenceNumber = result[keyID]
        for n in range(lastKnownSequenceNumber, lastSequenceNumber):
          postID = ('%s:post:%s' % (friendsID, n))
          # ask network for updates
          self.node.iterativeFindValue(postID).addCallback(self._processUpdatesResult)
    self.node.iterativeFindValue(keyID).addCallback(_processSequenceNumber)
    # NOTE(cskau): it's all deferred so we can't do much here
    # TODO(cskau): maybe just return cache?
    return delta

  def _signMessage(message):
    '''Signs the specified message using the node's private key.'''
    hashValue = SHA.new(message).digest()
    return self.RSAkey.sign(hashValue, '')

  def _verifyMessage(message, signature):
    '''Verify a message based on the specified signature.'''
    hashValue = SHA.new(message).digest()
    return RSAkey.verify(hashValue, signature)

  def _generateRandomString(length):
    '''Generates a random string with a byte length of "length".'''
    return "".join(chr(random.randrange(0, 256)) for i in xrange(length))

  ## ---- "Soft" API ----

  def addFriend(self, friendsID):
    # Add friends known ID to the friends set
    self.friends.add(friendsID)
    self.postCache[friendsID] = {}

  def getDigest(self, n = 10):
    digest = []
    """Gets latest n updates from friends"""
    for f in self.friends:
      # update post cache
      lastKnownPost = max(self.postCache[f].keys() + [0])
      # Do eventual update of cache
      #  Note: unfortunaly we can't block and wait for updates, so make do
      self.getUpdates(f, lastKnownPost)
      # get last n from this friend
      digest.append(sorted(self.postCache[f].items())[-n:])
    return sorted(digest)[-n:]

if __name__ == '__main__':
  import sys
  if len(sys.argv) < 2:
    print('Usage:\n%s UDP_PORT [KNOWN_NODE_IP KNOWN_NODE_PORT]' % sys.argv[0])
    sys.exit(1)
  else:
    try:
      usePort = int(sys.argv[1])
    except ValueError:
      print('\nUDP_PORT must be an integer value.\n')
      print(
          'Usage:\n%s UDP_PORT [KNOWN_NODE_IP KNOWN_NODE_PORT]' % sys.argv[0])
      sys.exit(1)

  if len(sys.argv) == 4:
    knownNodes = [(sys.argv[2], int(sys.argv[3]))]
  else:
    knownNodes = None

  # Create Tinfoil node, join network
  node = Node(udpPort=usePort)

  # Add HTTP "GUI"
  import tinfront
  httpPort = (usePort + 10000) % 65535
  front = tinfront.TinFront(httpPort, node)
  print('Front-end running at http://localhost:%i' % httpPort)

  node.join(knownNodes)

