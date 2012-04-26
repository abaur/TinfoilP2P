#!/usr/bin/env python
# coding: UTF-8


import Crypto.Random

CRYPTO_CHALLENGE_C1 = 2
CRYPTO_CHALLENGE_C2 = 4
NODE_ID_PREFIX_DIFFERS_BITS = 33

# Maybe call it compareNBits

def sharesXBitPrefix(value1, value2, prefixLength):
  """Compares the X first bits in the two specified values."""
  _value1, _value2 = value1, value2
  # if input was binary strings we need to first convert to ints
  if type(_value1) == str:
    _value1 = bin2int(_value1)
  if type(_value2) == str:
    _value2 = bin2int(_value2)
  # bitmask of all ones in the prefixLength lowest bits
  bitmask = ((2 ** prefixLength) - 1)
  return ((_value1 & bitmask) == (_value2 & bitmask))

def hasNZeroBitPrefix(value, n):
  """Check whether the first N bits in the specified value are all zero."""
  return ((value & ((2 ** n) - 1)) == 0)

def generateRandomString(length):
  """Generates a random string with a byte length of 'length'."""
  return Crypto.Random.get_random_bytes(length)

## converters 

def bin2int(value):
  """Converts binary to integer."""
  return long(value.encode('hex'), base = 16)

def int2bin(value, nbytes = 20):
  """Converts integer to binary."""
  return (hex(value)[2:-1].rjust((2 * nbytes), '0')).decode('hex')

def hex2int(value):
  """Converts hex to integer."""
  return long(value, base = 16)

def int2hex(value, nbytes = 20):
  """Converts integer to hex."""
  return hex(value)[2:-1].rjust((2 * nbytes), '0')

def hex2bin(value, nbytes = 20):
  return (value.rjust((2 * nbytes), '0')).decode('hex')

def hsh2int(value):
  """Converts a hex hash to integer."""
  return long(value.hexdigest(), base = 16)

