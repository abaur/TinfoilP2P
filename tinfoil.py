#!/usr/bin/env python
# coding: UTF-8

'''
  The Tinfoil social network client.
'''

from tintangled import EntangledNode
import twisted.internet.reactor

class Node:
  def __init__(self, udpPort=4000):
    self.udpPort = udpPort

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
  def share(self):
    pass

  ''' Unshare previously shared resource with one of more users.
    Ask network to delete specific, existing sharing keys.
    Note:
      This can never be safer than the network allows it.
      Malicious peer might simply keep the sharing keys despite all.
    Code Sketch:
      weakDelete(sharingKeys[resourceID][otherUserID])
  '''
  def unshare(self):
    pass

  ''' Post some resource to the network.
    Ask the network to store some (encrypted) resource.
    Note:
      This should be encrypted with a symmetric key which will be private
       until shared through the above share() method.
    Code Sketch:
      ...
  '''
  def post(self):
    pass

  ''' Check for and fetch new updates on user(s)
    Ask for latest known post from a given user and fetch delta since last
     fetched update.
    Code Sketch:
      latestSequenceNumber = get("latest(otherUserID)")
      latestPostID = hash(otherUserID + latestSequenceNumber)
      latestPost = get(latestPostID)
  '''
  def getUpdates(self):
    pass


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

