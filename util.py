#!/usr/bin/env python
# coding: UTF-8

# Maybe call it compareNBits
def sharesXBitPrefix(bitpattern1, bitpattern2, prefixLength):
  # bitmask of all ones in the prefixLength lowest bits
  bitmask = ((2 ** prefixLength) - 1)
  return ((bitpattern1 & bitmask) == (bitpattern2 & bitmask))

def hasNZeroBitPrefix(value, n):
  return ((value & ((2 ** n) - 1)) == 0)

