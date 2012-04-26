#!/usr/bin/env python
# coding: UTF-8

import Crypto.Random
import binascii

# Maybe call it compareNBits
def sharesXBitPrefix(bitpattern1, bitpattern2, prefixLength):
  """Compares the X first bits in the two specified bitpatterns."""
  # bitmask of all ones in the prefixLength lowest bits
  bitmask = ((2 ** prefixLength) - 1)
  return ((bitpattern1 & bitmask) == (bitpattern2 & bitmask))

def hasNZeroBitPrefix(value, n):
  """Check whether the first N bits in the specified value are all zero."""
  return ((value & ((2 ** n) - 1)) == 0)

def generateRandomString(length):
  """Generates a random string with a byte length of 'length'."""
  return Crypto.Random.get_random_bytes(length)

## converters 

def bin2int(value):
  """Converts binary to integer."""
  return int(binascii.hexlify(value), base = 16)

def int2bin(value):
  """Converts integer to binary."""
  return binascii.unhexlify(hex(value)[2:-1].rjust(40, '0'))

def hex2int(value):
  """Converts hex to integer."""
  return int(value, base = 16)

def int2hex(value):
  """Converts integer to hex."""
  return hex(value)[2:-1].rjust(40, '0')

def hex2bin(value):
  return binascii.unhexlify(value.rjust(40, '0'))

def hsh2int(value):
  """Converts a hex hash to integer."""
  return int(value.hexdigest(), base = 16)

