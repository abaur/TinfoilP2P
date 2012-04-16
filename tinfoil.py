#!/usr/bin/env python
# coding: UTF-8

'''
  The Tinfoil social network client.
'''

from tintangled import EntangledNode
import twisted.internet.reactor
from Crypto.Cipher import AES
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto import Random

class Node:
  def __init__(self, udpPort=4000):
    self.udpPort = udpPort
    # TODO(cskau): we need to ask the network for last known sequence number
    self.sequenceNumber = 0
    self.userID = None
    # TODO(cskau): maybe securely store these in the network so we don't 
    #  lose them. Retrieve every time we join.
    self.postKeys = {}
    self.random = Random.new()
    self.RSAkey = RSA.generate(2048, self.random.read)

  ''' Join the social network.
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
  def join(self, knownNodes):
    # TODO(cskau): this is just example code for now.
    # We need to modify underlying network protocol for the above.
    self.node = EntangledNode(udpPort=self.udpPort)
    self.node.joinNetwork(knownNodes)
    twisted.internet.reactor.run()
    # TODO(cskau): stub~~
    if "joining for the first time":
      self.userID = self._getRandomIDFromNetwork()
    else:
      self.userID = 'our previously issued ID'

  ''' Ask network to generate a pseudo random ID for us, a la FreeNet
  '''
  def _getRandomIDFromNetwork(self):
    # TODO(cskau): stub
    return 0

  ''' Share some stored resource with one or more users.
    Allow other user(s) to access store resource by issuing sharing key
     unique to the user-resource pair.
    Code Sketch:
      sharingKey[resourceID][otherUserID] = encrypt(
          publicKeys[otherUserID],
          resourceKeys[resourceID])
      store(
          "SharingKey(resourceID, otherUserID)",
          sharingKeys[resourceID][otherUserID])
  '''
  def share(self, resourceID, friendsID):
    sharingKeyID = ('%s:share:%s' % (resourceID, friendsID))
    sharingKey = self._encryptForUser(self.postKeys[resourceID], friendsID)
    self.node.publishData(sharingKeyID, sharingKey)

  ''' Encrypt some content assymetrically with user's public key
  '''
  def _encryptForUser(self, content, userID):
    userKey = self._getUserPublicKey(userID)
    return self._encryptKey(content, userKey)

  def _getUserPublicKey(self, userID):
    publicKeyID = ('%s:publickey' % (userID))
    return self.node.iterativeFindValue(publicKeyID)

  def _encryptKey(self, content, userKey):
    # TODO(cskau): stub
    return content

  ''' Unshare previously shared resource with one of more users.
    Ask network to delete specific, existing sharing keys.
    Note:
      This can never be safer than the network allows it.
      Malicious peer might simply keep the sharing keys despite all.
    Code Sketch:
      weakDelete(sharingKeys[resourceID][otherUserID])
  '''
  def unshare(self, resourceID, friendsID):
    shareKeyID = ('%s:share:%s' % (resourceID, friendsID))
    self.node.removeDate(shareKeyID)

  ''' Post some resource to the network.
    Ask the network to store some (encrypted) resource.
    Note:
      This should be encrypted with a symmetric key which will be private
       until shared through the above share() method.
    Code Sketch:
      ...
  '''
  def post(self, content):
    newSequenceNumber = self._getSequenceNumber()
    encryptedContent = self._encryptPost(key, content)
    # We need to store post keys used so we can issue sharing keys later
    self.postKeys[newSequenceNumber] = key
    postID = ('%s:post:%s' % (self.userID, newSequenceNumber))
    self.node.publishData(postID, encryptedContent)
    # update our latest sequence number
    self.node.publishData('%s:latest', newSequenceNumber)

  ''' Return next, unused sequence number unique to this user
  '''
  def _getSequenceNumber(self):
    # TODO(cskau): we probasbly need to ask the network to avoid sync errors
    #  a user might publish from multiple clients at a time
    self.sequenceNumber += 1
    return self.sequenceNumber

  ''' Encrypt a post with a symmetric key
  '''
  def _encryptPost(self, key, post):
    # TODO(cskau): This is a stub
    return post

  ''' Check for and fetch new updates on user(s)
    Ask for latest known post from a given user and fetch delta since last
     fetched update.
    Code Sketch:
      latestSequenceNumber = get("latest(otherUserID)")
      latestPostID = hash(otherUserID + latestSequenceNumber)
      latestPost = get(latestPostID)
  '''
  def getUpdates(self, friendsID, lastKnownSequenceNumber):
    latestSequenceNumber = self.node.iterativeFindValue(
        ('%s:latest' % (friendsID)))
    delta = {}
    for n in range(lastKnownSequenceNumber, latestSequenceNumber):
      postID = ('%s:post:%s' % (friendsID, n))
      delta[postID] = self.node.iterativeFindValue(postID)
    return delta

  # -*- Encryption Methods -*-

  # * Asymmetric(RSA) *

  def _signMessage(message):
    '''Signs the specified message using the node's private key.'''
    hash = SHA.new(message).digest()
    return self.RSAkey.sign(hash, random)

  def _verifyMessage(message, signature):
    '''Verify a message based on the specified signature.'''
    hash = SHA.new(message).digest()
    return RSAkey.verify(hash, signature)

  def _encryptMessageRSA(message):
    '''Encrypts the specified message using the node's private key.'''
    return self.RSAkey.encrypt(message, self.random.getrandbits(256))

  def _decryptMessageRSA(message):
    '''Decrypts the specified message using the node's private key.'''
    return self.RSAkey.decrypt(message)

  # * Symmetric(AES) *

  def _encryptMessageAES(message, key, nounce):
    '''Encrypts the specified message using AES.'''
    AESobj = AES.new(key, AES.MODE_CBC, nounce)
    return AESobj.encrypt(message)

  def _encryptMessageAES(message, key, nounce):
    '''Decrypts the specified message using the given key.'''
    AESobj = AES.new(key, AES.MODE_CBC, nounce)
    return AESobj.decrypt(message)

  def _generateSymmetricKey(length):
    '''Generates a key for symmetric encryption with a byte length of "length".'''
    return "".join(chr(random.randrange(0, 256)) for i in xrange(length))

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

