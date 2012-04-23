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

  def render_GET(self, request):
    self.numberRequests += 1
    request.setHeader("content-type", "text/html")
    return "I am request #" + str(self.numberRequests) + "\n"

