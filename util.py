#!/usr/bin/env python
# coding: UTF-8

import Crypto.Random
import binascii

CRYPTO_CHALLENGE_C1 = 2
CRYPTO_CHALLENGE_C2 = 4

# Maybe call it compareNBits
def sharesXBitPrefix(bitpattern1, bitpattern2, prefixLength):
  # bitmask of all ones in the prefixLength lowest bits
  bitmask = ((2 ** prefixLength) - 1)
  return ((bitpattern1 & bitmask) == (bitpattern2 & bitmask))

def hasNZeroBitPrefix(value, n):
  return ((value & ((2 ** n) - 1)) == 0)

def generateRandomString(length):
  '''Generates a random string with a byte length of "length".'''
  return Crypto.Random.get_random_bytes(length)

## converters 

def bin2int(value):
  return int(binascii.hexlify(value), base = 16)

def int2bin(value):
  return binascii.unhexlify(hex(value)[2:-1].rjust(40, '0'))

def hex2int(value):
  return int(value, base = 16)

def int2hex(value):
  return hex(value)[2:-1].rjust(40, '0')

def hsh2int(value):
  return int(value.hexdigest(), base = 16)

