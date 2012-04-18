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

class Node:

  def __init__(self, udpPort = 4000):
    """Initializes a Tinfoil Node."""
    self.udpPort = udpPort
    # TODO(cskau): we need to ask the network for last known sequence number
    self.sequenceNumber = 0
    self.userID = None
    # TODO(cskau): maybe securely store these in the network so we don't
    #  lose them. Retrieve every time we join.
    self.postKeys = {}
    self.secRandom = Random.new() # cryptographically safe Random function.
    self.RSAkey = RSA.generate(2048, self.secRandom.read)

    # NOTE(purbak): right now the public/private keys are just generated on
    # initialization of the node rather than on join. Is this a problem?
    # public key can be extracted using self.RSAkey.publickey()
    # i.e. self.publickey = self.RSAkey.publickey()

    # NOTE(purbak): Hard to find examples of crypto challenges online.
    # Alternatively, hash a string of sufficient length and let a newcomer
    # bruteforce it. (I can create a function for it if need be).

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
    self.node = EntangledNode(udpPort = self.udpPort)
    self.node.joinNetwork(knownNodes)
    twisted.internet.reactor.run()
    # TODO(cskau): stub~~
    if "joining for the first time":
      self.userID = self._getRandomIDFromNetwork()
    else:
      self.userID = 'our previously issued ID'

  def _getRandomIDFromNetwork(self):e some stored resource with one or more users.
  Allow other user(s) to access store resource by issuing sharing key
  unique to the user-resource pair.
  Code Sketch:
  sharingKey[resourceID][otherUserID] = encrypt(
  publicKeys[otherUserID],
  resourceKeys[resourceID])
  store(
  "SharingKey(resourceID, otherUserID)",
 
    """Ask network to generate a pseudo random ID for us, a la FreeNet"""
    # TODO(cskau): stub
    return 0

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
    # NOTE(purbak): using % is old-style python, use .format instead?
    sharingKeyID = ('%s:share:%s' % (resourceID, friendsID))
    sharingKey = self._encryptForUser(self.postKeys[resourceID], friendsID)
    self.node.publishData(sharingKeyID, sharingKey)

  def _encryptForUser(self, content, userID):
    """Encrypt some content asymetrically with user's public key."""
    userKey = self._getUserPublicKey(userID)
    return self._encryptKey(content, userKey)

  def _getUserPublicKey(self, userID):
    """Returns the public key corresponding to the specified userID, if any."""
    # NOTE(purbak): Why the concatenation?
    publicKeyID = ('%s:publickey' % (userID))
    return self.node.iterativeFindValue(publicKeyID)

  def _encryptKey(self, content, publicKey):
    """Encrypts content using the specified public key."""
    return publicKey.encrypt(content, '') # '' -> K not needed when using RSA.

  def _decryptKey(self, content):
    """Decrypts content  using node's own private key."""
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
    encryptedContent = self._encryptPost(key, content)
    # We need to store post keys used so we can issue sharing keys later
    self.postKeys[newSequenceNumber] = key
    postID = ('%s:post:%s' % (self.userID, newSequenceNumber))
    self.node.publishData(postID, encryptedContent)
    # update our latest sequence number
    self.node.publishData('%s:latest', newSequenceNumber)

  def _getSequenceNumber(self):
    """Return next, unused sequence number unique to this user."""
    # TODO(cskau): we probasbly need to ask the network to avoid sync errors
    #  a user might publish from multiple clients at a time
    self.sequenceNumber += 1
    return self.sequenceNumber

  def _encryptPost(self, key, post):
    """Encrypt a post with a symmetric key.

    @param key: must be 16, 24, or 32 bytes long.
    @type key: str

    """
    # NOTE(purbak): what to do about the nounce bit of the message.
    # Idea: randomly generate a nounce and send along with the private key.
    nounce = 'abcdefghijklmnop' # TODO(purbak): Something else.
    AESkey = AES.new(key, AES.MODE_CBC, nounce)
    return AESkey.encrypt(post)

  def _decryptPost(self, key, post):
    """Decrypt a post with a symmetric key.

    @param key: must be 16, 24, or 32 bytes long.
    @type key: str

    """
    # NOTE(purbak): what to do about the nounce bit of the message.
    nounce = 'abcdefghijklmnop' # TODO(purbak): Something else.
    AESkey = AES.new(key, AES.MODE_CBC, nounce)
    return AESkey.decrypt(post)

  def getUpdates(self, friendsID, lastKnownSequenceNumber):
    """ Check for and fetch new updates on user(s)
    Ask for latest known post from a given user and fetch delta since last
    fetched update.
    Code Sketch:
    latestSequenceNumber = get("latest(otherUserID)")
    latestPostID = hash(otherUserID + latestSequenceNumber)
    latestPost = get(latestPostID)
    """
    latestSequenceNumber = self.node.iterativeFindValue(
      ('%s:latest' % (friendsID)))
    delta = {}
    for n in range(lastKnownSequenceNumber, latestSequenceNumber):
      postID = ('%s:post:%s' % (friendsID, n))
      delta[postID] = self.node.iterativeFindValue(postID)
    return delta

  # -*- Other Encryption Methods -*-

  def _signMessage(message):
    """Signs the specified message using the node's private key."""
    hash = SHA.new(message).digest()
    return self.RSAkey.sign(hash, '')

  def _verifyMessage(message, signature):
    """Verify a message based on the specified signature."""
    hash = SHA.new(message).digest()
    return RSAkey.verify(hash, signature)

  def _generateSymmetricKey(length):
    """Generates a key for symmetric encryption with a byte length of "length"."""
    return ''.join(chr(random.randrange(0, 256)) for i in xrange(length))

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
  node.join(knownNodes)
  # TODO(cskau): go into interactive mode ?

