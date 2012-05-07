#!/usr/bin/env python


import os
import sys
import time
import signal


def forNodes(nodes, func, i = 0):
  for node in nodes:
    hashAmount = ((i * 50) / amount)
    hashbar = ('#' * hashAmount)
    output = '\r[%-50s] %d/%d' % (hashbar, i, amount)
    sys.stdout.write(output)
    func(node, i)
    time.sleep(0.15)
    i += 1

def destroyNetwork(nodes):
  print 'Destroying network...'
  forNodes(
      nodes,
      (lambda node, i: os.kill(node, signal.SIGTERM)))
  print

if __name__ == '__main__':
  if len(sys.argv) < 2:
    print 'Usage:\n%s AMOUNT_OF_NODES [NIC_IP_ADDRESS]' % sys.argv[0]
    print '\nNIC_IP_ADDRESS should be the IP address of the network interface through'
    print 'which other systems will access these nodes.\n'
    print 'If omitted, the script will attempt to determine the system\'s IP address'
    print 'automatically, but do note that this may result in 127.0.0.1 being used (i.e.'
    print 'the nodes will only be reachable from this system).\n'
    sys.exit(1)
  amount = int(sys.argv[1])
  if len(sys.argv) >= 3:
    ipAddress = sys.argv[2]
  else:
    import socket
    ipAddress = socket.gethostbyname(socket.gethostname())
    print 'Network interface IP address omitted; using %s...' % ipAddress

  scenario_file = None
  if len(sys.argv) >= 4:
    import urllib2
    scenario_file = open(sys.argv[3])

  startPort = 4000
  port = (startPort + 1)
  nodes = []
  print 'Creating Kademlia network...'
  try:
    nodes.append(os.spawnlp(
        os.P_NOWAIT,
        'python',
        'python',
        './tinfoil.py',
        str(startPort)))
    # Crypto ID need time to generate..
    time.sleep(1.0)
    forNodes(
        # we're cheating a bit - it's actually a port range
        range(port, (port + (amount - 1))),
        (lambda port, i:
            nodes.append(os.spawnlp(
                os.P_NOWAIT,
                'python',
                'python',
                './tinfoil.py',
                str(port), # the node var contains the port number ..
                ipAddress,
                str(startPort)))))
  except KeyboardInterrupt:
    '\nNetwork creation cancelled.'
    destroyNetwork(nodes)
    sys.exit(1)

  print '\n\n---------------\nNetwork running\n---------------\n'

  try:
    # run scenario script (a bunch of HTTP GETs)
    raw_input('Press enter to start scenario..')
    import re
    r = re.compile('Your ID is: (.*)\n')
    import hashlib
    # hack-hack-hack ...
    class HackyDict(dict):
      def __getitem__(self, key):
        if not dict.has_key(self, key):
          return hashlib.sha1(
              dict.get(self, key[:5]) + key[5:]).digest().encode('hex')
        return dict.get(self, key)
    scenarioDict = HackyDict()
    for port in range(startPort, (port + (amount - 1))):
      html = urllib2.urlopen('http://localhost:2%s' % (port)).read()
      scenarioDict['2%s' % port] = r.search(html).group(1)
    if scenario_file:
      for line in scenario_file:
        url = line.strip().split('#')[0]
        if len(url):
          print(url % scenarioDict)
          urllib2.urlopen(url % scenarioDict)
          time.sleep(0.3)
    # sleep while network is runnning
    while 1:
      time.sleep(1)
  except KeyboardInterrupt, e:
    print(e)
    pass
  finally:
    destroyNetwork(nodes)

