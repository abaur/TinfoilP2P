#!/usr/bin/env python
# coding: UTF-8


import twisted.web.server
import twisted.web.resource

import util


class TinFront(twisted.web.resource.Resource):
  isLeaf = True
  numberRequests = 0

  def __init__(self, port, node):
    """Initializes the TinFront."""
    self.port = port
    self.node = node
    twisted.internet.reactor.listenTCP(
        self.port,
        twisted.web.server.Site(self))

  def _handleRequest(self, request):
    """Handles the request."""
    path = request.uri.split('?')[0]
    query = (
        request.uri.split('?')[1]
            if len(request.uri.split('?')) == 2
            else '')
    if path == '/addfriend':
      if query.startswith('friendsid='):
        friendsID = util.hex2bin(query[10:])
        self.node.addFriend(friendsID)
    elif path == '/post':
      if query.startswith('content='):
        content = query[8:]
        self.node.post(content)
    elif path == '/share':
      postID, friendsID = query.split('&')
      self.node.share(postID[7:], friendsID[10:])
    else:
      print(request.uri)

  def render_GET(self, request):
    """Renders the result of the GET request."""
    self._handleRequest(request)
    self.numberRequests += 1
    request.setHeader("content-type", "text/html")
    return (
      '''<h1>Welcome to TinFoil Net</h1>
      Your ID is: %(id)s
      <form action="/post" method="get">
        <input type="text" name="content" placeholder="What's on your mind?" />
      </form>
      Digest:
      <ul>
        %(digest)s
      </ul>
      <form action="/addfriend" method="get">
        <input type="text" name="friendsid" placeholder="Add friend by ID" />
      </form>''' % {
        'digest': self.node.getDigest(),
        'id': util.bin2hex(self.node.node.id),
      })

