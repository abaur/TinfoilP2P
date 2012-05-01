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
      self.node.share(
          util.hex2bin(postID[7:]),
          util.hex2bin(friendsID[10:]))
    else:
      print(request.uri)

  def getDigestRender(self, digest):
    import urllib
    result = ''
    for friendsID in digest:
      result += ('<li><h2>%s</h2></li>\n' % (util.bin2hex(friendsID)))
      for postNumber, postDict in digest[friendsID]:
        if 'postp' in postDict:
          result += ('<li><p>%s: %s</p><small>%s</small></li>\n' % (
              postNumber,
              urllib.unquote_plus(postDict['postp']),
              util.bin2hex(postDict['id'])))
        else:
          result += ('<li><p>%s: <i>%s</i></p><small>%s</small></li>\n' % (
              postNumber,
              util.bin2hex(postDict['post']),
              util.bin2hex(postDict['id'])))
    return result

  def render_GET(self, request):
    """Renders the result of the GET request."""
    self._handleRequest(request)
    self.numberRequests += 1
    request.setHeader("content-type", "text/html")
    return (
      '''<h1>Welcome to <a href="/">TinFoil Net</a></h1>
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
      </form>
      Share:
      <form action="/share" method="get">
        <input type="text" name="postid" placeholder="Post's ID" />
        <input type="text" name="friendsid" placeholder="Friend's ID" />
      </form>
      ''' % {
        'digest': self.getDigestRender(self.node.getDigest()),
        'id': util.bin2hex(self.node.node.id),
      })

