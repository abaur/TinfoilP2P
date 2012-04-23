#!/usr/bin/env python
# coding: UTF-8

def sharesXBitPrefix(bitpattern1,bitpattern2,prefixLength):
	bitpattern1LowerBits = (2**prefixLength-1) & bitpattern1
	bitpattern2LowerBits = (2**prefixLength-1) & bitpattern2
    return bitpattern2LowerBits & bitpattern1LowerBits != 0