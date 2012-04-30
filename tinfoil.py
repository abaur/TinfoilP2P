#!/usr/bin/env python
# coding: UTF-8

"""The Tinfoil social network client."""

import entangled.kademlia.contact
import twisted.internet.reactor
import Crypto
import Crypto.Cipher.AES
import Crypto.Hash.SHA
import Crypto.PublicKey.RSA
import Crypto.Random

from node import TintangledNode
import constants
import util

import binascii

class Client:
  '''A TinFoil Net client
  Builds the "social" features ontop of the underlying network framework.
  '''

  def __init__(self, udpPort = 4000):
    '''Initializes a Tinfoil Node.'''
    self.udpPort = udpPort
    self.postCache = {}
    # TODO(cskau): we need to ask the network for last known sequence number
    self.sequenceNumber = 0
    self.friends = set()
    # TODO(cskau): Retrieve these every time we re-join.
    self.postKeys = {}
    self.postIDNameTuple = {}

  def join(self, knownNodes):
    """Join the social network.
    Calculate our userID and join network at given place.
    This involves:
    - generating a random ID by solving cryptographic puzzles,
      which serves as a guard against Sybil attacks.
    - generate public and private keys for new id.
    - notifying and requesting involved parties of the selected position.
    OR if the user has already created his ID in the past.
    - use the previously established private key to authenticate in network.
    """
    self.node = TintangledNode(udpPort = self.udpPort) # also generates the ID.
    self.node.joinNetwork(knownNodes)
    print('Your ID is: %s   - Tell your friends!' %
        binascii.hexlify(self.node.id))
    # Add ourself to our friends list, so we can see our own posts too..
    self.addFriend(self.node.id)
    self.node.publishData(self.node.id, self._getUserPublicKey(self.node.id))
    twisted.internet.reactor.run()

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
    if userID == self.node.id:
      return self.node.rsaKey
    publicKeyID = ('%s:publickey' % (userID))
    # TODO(cskau): This is a defer !!
    publicKeyDefer = self.node.iterativeFindValue(publicKeyID)
    return None

  def _encryptKey(self, content, publicKey):
    """Encrypts content (sharing key) using the specified public key."""
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
    postKey = util.generateRandomString(constants.SYMMETRIC_KEY_LENGTH)
    nonce = util.generateRandomString(constants.NONCE_LENGTH)
    encryptedContent = self._encryptPost(postKey, nonce, content)
    # We need to store post keys used so we can issue sharing keys later
    # TODO(cskau): whenever we update this, we should store it securely in net
    self.postKeys[newSequenceNumber] = postKey
    postID = ('%s:post:%s' % (self.node.id, newSequenceNumber))
    postDefer = self.node.publishData(postID, encryptedContent)
    # update our latest sequence number
    latestID = ('%s:latest' % (self.node.id))
    latestDefer = self.node.publishData(latestID, newSequenceNumber)
    # store post key by sharing the post with ourself
    self.share(newSequenceNumber, self.node.id)

  def _getSequenceNumber(self):
    """Return next, unused sequence number unique to this user."""
    # TODO(cskau): we probably need to ask the network to avoid sync errors.
    #  Case: a user might publish from multiple clients at a time.
    self.sequenceNumber += 1
    return self.sequenceNumber

  def _encryptPost(self, key, nonce, post):
    """Encrypt a post with a symmetric key.

    @param key: must be 16, 24, or 32 bytes long.
    @type key: str

    """

    if not len(key) in [16, 24, 32]:
      raise 'Specified key had an invalid key length, it should be 16, 24 or 32.'
    if len(nonce) != constants.NONCE_LENGTH:
      raise 'Specified nonce had an invalid key length, it should be 16.'

    aesKey = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, nonce)
    # NOTE(cskau): *input* has to be a 16-multiple, pad with whitespace
    return aesKey.encrypt(post + (' ' * (16 - (len(post) % 16))))

  def _decryptPost(self, key, nonce, post):
    """Decrypt a post with a symmetric key.

    @param key: must be 16, 24, or 32 bytes long.
    @type key: str

    """

    if not len(key) in [16, 24, 32]:
      raise 'Specified key had an invalid key length, it should be 16, 24 or 32.'
    if len(nonce) != constants.NONCE_LENGTH:
      raise 'Specified nonce had an invalid key length, it should be 16.'

    aesKey = Crypto.Cipher.AES.new(key, Crypto.Cipher.AES.MODE_CBC, nonce)
    decryptedMessage = aesKey.decrypt(post)
    # remove any whitespace padding.
    return decryptedMessage.strip()

  def _processUpdatesResult(self, result):
    """Process post updates when we get them as callbacks."""
    for resultKey in result:
      print(resultKey)
      if type(resultKey) == entangled.kademlia.contact.Contact:
        print("WARN: key not found!")
        return
      postID = resultKey
      friendsID, n = self.postIDNameTuple[postID]
      self.postCache[friendsID][n] = result[postID]

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
    keyName = '%s:latest' % (friendsID)
    keyID = self.node.getNameID(keyName)
    def _processSequenceNumber(result):
      if type(result) == dict:
        lastSequenceNumber = result[keyID]
        for n in range(lastKnownSequenceNumber, (lastSequenceNumber + 1)):
          # There isn't actually any post 0 (which is kinda stupid..)
          if n == 0:
            continue
          postName = ('%s:post:%s' % (friendsID, n))
          postID = self.node.getNameID(postName)
          self.postIDNameTuple[postID] = (friendsID, n)
          # ask network for updates
          self.node.iterativeFindValue(postID).addCallback(
              self._processUpdatesResult)
    self.node.iterativeFindValue(keyID).addCallback(_processSequenceNumber)
    # NOTE(cskau): it's all deferred so we can't do much here
    # TODO(cskau): maybe just return cache?
    return delta

  def _signMessage(self, message):
    '''Signs the specified message using the node's private key.'''
    hashValue = Crypto.Hash.SHA.new(message).digest()
    return self.node.rsaKey.sign(hashValue, '') # Extra parameter not relevant for RSA.

  def _verifyMessage(self, message, signature):
    '''Verify a message based on the specified signature.'''
    hashValue = Crypto.Hash.SHA.new(message).digest()
    return self.node.rsaKey.verify(hashValue, signature)

  ## ---- "Soft" API ----

  def addFriend(self, friendsID):
    """Adds the specified friendsID to the user's friend set."""
    if len(friendsID) != constants.ID_LENGTH:
      raise 'Malformed ID'
    self.friends.add(friendsID)
    self.postCache[friendsID] = {}

  def getDigest(self, n = 10):
    """Gets latest n updates from friends."""
    digest = []
    for f in self.friends:
      # update post cache
      lastKnownPost = max([0] + self.postCache[f].keys())
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
  client = Client(udpPort=usePort)

  # Add HTTP "GUI"
  import tinfront
  httpPort = (usePort + 20000) % 65535
  front = tinfront.TinFront(httpPort, client)
  print('Front-end running at http://localhost:%i' % httpPort)

  client.join(knownNodes)

# end-of-tinfoil.py
