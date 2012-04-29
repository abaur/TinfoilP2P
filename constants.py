
CRYPTO_CHALLENGE_C1 = 2

CRYPTO_CHALLENGE_C2 = 2

RSA_BITS = 2048      
ID_LENGTH = 20 # in bytes

#This is taken from kademlia (#allans TODO how to fix import clashing with kademlia constants)
rpcTimeout = 5


# from s/kademlia: valid sender addresses are only added to a bucket if 
# the nodeId prefix differs in an appropriate amount of bits x (for example x > 32).
NODE_ID_PREFIX_DIFFERS_BITS = 33