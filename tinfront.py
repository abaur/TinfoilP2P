#!/usr/bin/env python
# coding: UTF-8

import twisted.web.server
import twisted.web.resource

class TinFront(twisted.web.resource.Resource):
  isLeaf = True
  numberRequests = 0

  def __init__(self, port, node):
    self.port = port
    self.node = node
    twisted.internet.reactor.listenTCP(
        self.port,
        twisted.web.server.Site(self))

  def _handleRequest(self, request):
    if request.uri.startswith('/?friendsid='):
      friendsID = request.uri[12:]
      self.node.addFriend(friendsID)

  def render_GET(self, request):
    self._handleRequest(request)
    self.numberRequests += 1
    request.setHeader("content-type", "text/html")
    return (
      '''<h1>Welcome to TinFoil Net</h1>
Digest:
<ul>
  %(digest)s
</ul>
<form action="?addfriend" method="get">
  Add friend by ID:
  <input type="text" name="friendsid"></input>
</form>''' % {
        'digest': self.node.getDigest()
      })

