#!/usr/bin/env python
# coding: UTF-8

# Used to store node authentication data.
PATH_TO_TMP = '/tmp'
PATH_TO_ID = PATH_TO_TMP + '/tinfoil_id.tmp'
PATH_TO_RSAKEY = PATH_TO_TMP + '/tinfoil_rsakey.tmp'
PATH_TO_X = PATH_TO_TMP + '/tinfoil_x.tmp'

RSA_BITS = 2048
ID_LENGTH = 20 # in bytes

SYMMETRIC_KEY_LENGTH = 32 # (bytes)
NONCE_LENGTH = 16 # (bytes)

#This is taken from kademlia (#allans TODO how to fix import clashing with kademlia constants)
rpcTimeout = 5

CRYPTO_CHALLENGE_C1 = 2
CRYPTO_CHALLENGE_C2 = 4

# from s/kademlia: valid sender addresses are only added to a bucket if
# the nodeId prefix differs in an appropriate amount of bits x (for example x > 32).
NODE_ID_PREFIX_DIFFERS_BITS = 33
