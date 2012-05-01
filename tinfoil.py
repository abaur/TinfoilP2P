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
import os
import pickle


class Client:
  '''A TinFoil Net client
  Builds the "social" features ontop of the underlying network framework.
  '''

  def __init__(self, udpPort = 4000):
    '''Initializes a Tinfoil Node.'''
    self.udpPort = udpPort
    self.postCache = {}
    # Local store of public keys of other nodes in the network
    self.keyCache = {}
    # TODO(cskau): we need to ask the network for last known sequence number
    self.sequenceNumber = 0
    self.friends = set()
    # TODO(cskau): Retrieve these every time we re-join.
    self.sharingKeys = {}
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

    # Check to see if we have already been authenticated with the network.
    id = None
    rsaKey = None
    x = None

    if os.path.exists(constants.PATH_TO_ID):
      fID = open(constants.PATH_TO_ID, 'r')
      id = fID.read()
      fID.close()

      fKey = open(constants.PATH_TO_RSAKEY, 'r')
      rsaKey = pickle.load(fKey)
      fKey.close()

      fX = open(constants.PATH_TO_X, 'r')
      x = long(fX.read())
      fX.close()

    # Generate new node from scratch or based on already known values.
    self.node = TintangledNode(id = id, udpPort = self.udpPort)

    # Save node data to file if node is new.
    if id == None:
      # Save ID, RSAKey and X to file.
      fID = open(constants.PATH_TO_ID, 'w')
      fID.write(self.node.id)
      fID.close()

      fKey = open(constants.PATH_TO_RSAKEY, 'w')
      pickle.dump(self.node.rsaKey, fKey)
      fKey.close()

      fX = open(constants.PATH_TO_X, 'w')
      fX.write(str(self.node.x))
      fX.close()
    else:
      self.node.rsaKey = rsaKey
      self.node.x = x
      # Alternative: add rsaKey and x as optional parameters in
      # TintangledNode.__init__.

    self.node.joinNetwork(knownNodes)
    print('Your ID is: %s   - Tell your friends!' % self.node.id.encode('hex'))
    self.keyCache[self.node.id] = self.node.rsaKey
    # Add ourself to our friends list, so we can see our own posts too..
    self.addFriend(self.node.id)
    self.node.publishData(
        ('%s:publickey' % (self.node.id)),
        pickle.dumps(self._getUserPublicKey(self.node.id).publickey()))
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
    sharingKeyEncrypted = self._encryptForUser(
        self.sharingKeys[resourceID],
        friendsID)
    # We might not have user's public key yet..
    if sharingKeyEncrypted is not None:
      self.node.publishData(sharingKeyID, sharingKeyEncrypted)
    else:
      print('Couldn\'t share. Key not found.')

  def _encryptForUser(self, content, userID, callback = None):
    """Encrypt some content asymetrically with user's public key."""
    userKey = self._getUserPublicKey(userID, callback)
    if userKey is None:
      return None
    return self._encryptKey(content, userKey)

  def _getUserPublicKey(self, userID, callback = None):
    """Returns the public key corresponding to the specified userID, if any."""
    if userID in self.keyCache:
      return self.keyCache[userID]
    publicKeyName = ('%s:publickey' % (userID))
    publicKeyID = self.node.getNameID(publicKeyName)
    # TODO(cskau): This is a defer !!
    publicKeyDefer = self.node.iterativeFindValue(publicKeyID)
    def _addPublicKeyToLocalCache(result):
      if type(result) == dict:
        for r in result:
          self.keyCache[userID] = pickle.loads(result[r])
    publicKeyDefer.addCallback(_addPublicKeyToLocalCache)
    if callback is not None:
      publicKeyDefer.addCallback(callback)
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
    #nonce = util.generateRandomString(constants.NONCE_LENGTH)
    # Use sequence number as nonce - that way we dont need to include it
    nonce = util.int2bin(newSequenceNumber, nbytes = constants.NONCE_LENGTH)
    encryptedContent = self._encryptPost(postKey, nonce, content)
    postName = ('%s:post:%s' % (self.node.id, newSequenceNumber))
    postID = self.node.getNameID(postName)
    # We need to remember post keys used so we can issue sharing keys later
    self.sharingKeys[postID] = postKey
    postDefer = self.node.publishData(postName, encryptedContent)
    # update our latest sequence number
    latestName = ('%s:latest' % (self.node.id))
    latestDefer = self.node.publishData(latestName, newSequenceNumber)
    # store post key by sharing the post with ourself
    self.share(postID, self.node.id)

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
      if type(resultKey) == entangled.kademlia.contact.Contact:
        print("WARN: key not found!")
        return
      postID = resultKey
      friendsID, n = self.postIDNameTuple[postID]
      self.postCache[friendsID][n] = {
        'post': result[postID],
        'id': postID,
      }

  def getUpdates(self, friendsID, lastKnownSequenceNumber):
    """ Check for and fetch new updates on user(s)
    Ask for latest known post from a given user and fetch delta since last
     fetched update.
    Code Sketch:
      latestSequenceNumber = get("latest(otherUserID)")
      latestPostID = hash(otherUserID + latestSequenceNumber)
      latestPost = get(latestPostID)
    """
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
          # ask for sharing keys too
          sharingKeyName = ('%s:share:%s' % (postID, self.node.id))
          sharingKeyID = self.node.getNameID(sharingKeyName)
          def _processSharingKeyResult(result):
            if type(result) == dict:
              for r in result:
                self.sharingKeys[postID] = self.node.rsaKey.decrypt(
                    result[r][0])
          self.node.iterativeFindValue(sharingKeyID).addCallback(
              _processSharingKeyResult)
    self.node.iterativeFindValue(keyID).addCallback(_processSequenceNumber)
    # NOTE(cskau): it's all deferred so we can't do much here
    # TODO(cskau): maybe just return cache?

  ## ---- "Soft" API ----

  def addFriend(self, friendsID):
    """Adds the specified friendsID to the user's friend set."""
    if len(friendsID) != constants.ID_LENGTH:
      raise 'Malformed ID'
    self.friends.add(friendsID)
    self.postCache[friendsID] = {}

  def getDigest(self, n = 10):
    """Gets latest n updates from friends."""
    digest = {}
    for f in self.friends:
      # update post cache
      lastKnownPost = max([0] + self.postCache[f].keys())
      # Do eventual update of cache
      #  Note: unfortunaly we can't block and wait for updates, so make do
      self.getUpdates(f, lastKnownPost)
    for f in self.friends:
      for k in self.postCache[f].keys()[-n:]:
        postID = self.postCache[f][k]['id']
        if postID in self.sharingKeys:
          self.postCache[f][k].update({'key': self.sharingKeys[postID]})
          self.postCache[f][k].update({'postp':
              self._decryptPost(
                  self.sharingKeys[postID],
                  util.int2bin(k, nbytes = constants.NONCE_LENGTH),
                  self.postCache[f][k]['post'])})
      # get last n from this friend
      digest[f] = self.postCache[f].items()[-n:][::-1]
    return digest


if __name__ == '__main__':
  import sys
  if len(sys.argv) < 2:
    print('Usage:\n%s UDP_PORT [KNOWN_NODE_IP KNOWN_NODE_PORT] NODE_ID' %
          sys.argv[0])
    sys.exit(1)
  else:
    try:
      usePort = int(sys.argv[1])
    except ValueError:
      print('\nUDP_PORT must be an integer value.\n')
      print(
          'Usage:\n%s UDP_PORT [KNOWN_NODE_IP KNOWN_NODE_PORT] NODE_ID' %
          sys.argv[0])
      sys.exit(1)

  if len(sys.argv) >= 4:
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
