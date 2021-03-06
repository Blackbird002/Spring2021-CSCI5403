import binascii # Convert between binary and ASCII
import sys
import os.path
import logging
import argparse

################################################################
# The MD5 Message-Digest Algorithm

# Resources:
# RFC-1321 : https://tools.ietf.org/html/rfc1321
# https://blog.jpolak.org/?p=1985
################################################################

################################################################
# 32-bit 
################################################################
INT_BITS = 32
 
################################################################
# Table of 64 elements where K[i] = abs(sin(i+1)) * 2^32
# Pseudo-random numbers that have desirable properties
################################################################
K = [  0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 
        0x4787c62a, 0xa8304613, 0xfd469501, 0x698098d8, 0x8b44f7af,
        0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 
        0x49b40821, 0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 
        0xd62f105d, 0x2441453, 0xd8a1e681, 0xe7d3fbc8, 0x21e1cde6, 
        0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 
        0x676f02d9, 0x8d2a4c8a, 0xfffa3942, 0x8771f681, 0x6d9d6122, 
        0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70, 
        0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x4881d05, 0xd9d4d039,
        0xe6db99e5, 0x1fa27cf8, 0xc4ac5665, 0xf4292244, 0x432aff97,
        0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 
        0x85845dd1, 0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 
        0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391              ]

################################################################
# Constants for MD5Transform routine (bit shift amounts)
# These repeat 4 times within a round
################################################################

# Round 1
S1 = [7,12,17,22]

# Round 2
S2 = [5,9,14,20]

# Round 3
S3 = [4,11,16,23]

# Round 4
S4 = [6,10,15,21]
 
# Circular bit-shift helper function
def leftCircularShift(k ,bits):
    bits = bits % INT_BITS
    k = k % (2**INT_BITS)     # k = k mod (2^32)
    upper = (k << bits) % (2**INT_BITS) 
    result = upper | (k >> (INT_BITS - (bits)))
    return result
 
def blockDivide(block, chunks):
    result = []
    size = len(block) // chunks
    for i in range(0, chunks):
        result.append( int.from_bytes(block[i * size:(i+1) * size], byteorder="little"))
    return result
 
################################################################
# Basic Functions F, G, H, I
################################################################

# For 0 <= step# <= 15
def F(X,Y,Z):
    return((X & Y)|((~X) & Z))
 
# For 16 <= step# <= 31
def G(X,Y,Z):
    return((X & Z)|(Y &(~Z)))
 
# For 32 <= step# <= 47
def H(X,Y,Z):
    return(X^Y^Z)

# For 48 <= step# <= 63
def I(X,Y,Z):
    return(Y^(X|(~Z)))

################################################################
# FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
################################################################
 
def FF(a, b, c, d, x, s, ac):
    a += F(b,c,d) + x + ac
    a = leftCircularShift(a,s)
    return a + b

def GG(a, b, c, d, x, s, ac):
    a += G(b,c,d) + x + ac
    a = leftCircularShift(a,s)
    return a + b
 
def HH(a, b, c, d, x, s, ac):
    a += H(b,c,d) + x + ac
    a = leftCircularShift(a,s)
    return a + b
 
def II(a, b, c, d, x, s, ac):
    a += I(b,c,d) + x + ac
    a = leftCircularShift(a,s)
    return a + b
 
# Formats num as a hexadecimal value in little byteorder
def convertToLittleHex(num):
    bigHex = "{0:08x}".format(num)

    # Return the binary data represented by the hexadecimal string
    bin = binascii.unhexlify(bigHex)
    result = "{0:08x}".format(int.from_bytes(bin,byteorder='little'))
    return result
 
# Gets the length in bits
def bitlen(bitstring):
    return(len(bitstring)*8)
 
def md5sum(msg):
    #Step #1 Append Padding Bits
    msgLen = bitlen(msg) % (2**64)
    msg = msg + b'\x80'
    zeroPad = (448 - (msgLen+8)%512)%512
    zeroPad //= 8
    msg = msg + b'\x00' * zeroPad 

    lenghOfMsg = bitlen(msg)

    if args.verbose:
        logger.info("Message length after paddding: {} Bits".format(lenghOfMsg))

    # Check if padded message is congruent to 448 modulo 512
    assert(lenghOfMsg % (512) == 448)

    if args.verbose:
        logger.info("{} modulo 512 == 448".format(lenghOfMsg))

    # Step #2 Append Length
    msg += msgLen.to_bytes(8,byteorder='little')

    msgLen = bitlen(msg)
    iterations = msgLen // 512

    if args.verbose:
        logger.info("Loop iterations (# of blocks): {}".format(iterations))

    # Step#3: Initialize MD Buffer (Initialization Vector - IV)
    '''
    word A: 01 23 45 67
    word B: 89 ab cd ef
    word C: fe dc ba 98
    word D: 76 54 32 10
    '''
    A = 0x67452301 
    B = 0xefcdab89
    C = 0x98badcfe
    D = 0x10325476

    # Step #4: Process Message in 16-Word Blocks
    #Main loop
    for i in range(0,iterations):

        # Start out with MD5 specific initialization vector (IV)
        a = A
        b = B
        c = C
        d = D

        # Get the next block i to process
        block = msg[i*64:(i+1)*64]
        M = blockDivide(block,16)
        if args.verbose:
            print("Processing block {}: {}".format(i, M))

        # For each block we perform 4 rounds where each round has 16 operations (Total of 64). 

        #Round 1
        a = FF( a,b,c,d, M[0], S1[0], K[0] )           #1
        d = FF( d,a,b,c, M[1], S1[1], K[1] )           #2
        c = FF( c,d,a,b, M[2], S1[2], K[2] )           #3
        b = FF( b,c,d,a, M[3], S1[3], K[3] )           #4
        a = FF( a,b,c,d, M[4], S1[0], K[4] )           #5
        d = FF( d,a,b,c, M[5], S1[1], K[5] )           #6
        c = FF( c,d,a,b, M[6], S1[2], K[6] )           #7
        b = FF( b,c,d,a, M[7], S1[3], K[7] )           #8
        a = FF( a,b,c,d, M[8], S1[0], K[8] )           #9
        d = FF( d,a,b,c, M[9], S1[1], K[9] )           #10
        c = FF( c,d,a,b, M[10], S1[2], K[10] )         #11
        b = FF( b,c,d,a, M[11], S1[3], K[11] )         #12
        a = FF( a,b,c,d, M[12], S1[0], K[12] )         #13
        d = FF( d,a,b,c, M[13], S1[1], K[13] )         #14
        c = FF( c,d,a,b, M[14], S1[2], K[14] )         #15
        b = FF( b,c,d,a, M[15], S1[3], K[15] )         #16

        # Round 2
        a = GG( a,b,c,d, M[1], S2[0], K[16] )          #17
        d = GG( d,a,b,c, M[6], S2[1], K[17] )          #18
        c = GG( c,d,a,b, M[11], S2[2], K[18] )         #19
        b = GG( b,c,d,a, M[0], S2[3], K[19] )          #20
        a = GG( a,b,c,d, M[5], S2[0], K[20] )          #21
        d = GG( d,a,b,c, M[10], S2[1], K[21] )         #22
        c = GG( c,d,a,b, M[15], S2[2], K[22] )         #23
        b = GG( b,c,d,a, M[4], S2[3], K[23] )          #24
        a = GG( a,b,c,d, M[9], S2[0], K[24] )          #25
        d = GG( d,a,b,c, M[14], S2[1], K[25] )         #26
        c = GG( c,d,a,b, M[3], S2[2], K[26] )          #27
        b = GG( b,c,d,a, M[8], S2[3], K[27] )          #28
        a = GG( a,b,c,d, M[13], S2[0], K[28] )         #29
        d = GG( d,a,b,c, M[2], S2[1], K[29] )          #30
        c = GG( c,d,a,b, M[7], S2[2], K[30] )          #31
        b = GG( b,c,d,a, M[12], S2[3], K[31] )         #32

        # Round 3
        a = HH( a,b,c,d, M[5], S3[0], K[32] )          #33
        d = HH( d,a,b,c, M[8], S3[1], K[33] )          #34
        c = HH( c,d,a,b, M[11], S3[2], K[34] )         #35
        b = HH( b,c,d,a, M[14], S3[3], K[35] )         #36
        a = HH( a,b,c,d, M[1], S3[0], K[36] )          #37
        d = HH( d,a,b,c, M[4], S3[1], K[37] )          #38
        c = HH( c,d,a,b, M[7], S3[2], K[38] )          #39
        b = HH( b,c,d,a, M[10], S3[3], K[39] )         #40
        a = HH( a,b,c,d, M[13], S3[0], K[40] )         #41
        d = HH( d,a,b,c, M[0], S3[1], K[41] )          #42
        c = HH( c,d,a,b, M[3], S3[2], K[42] )          #43
        b = HH( b,c,d,a, M[6], S3[3], K[43] )          #44
        a = HH( a,b,c,d, M[9], S3[0], K[44] )          #45
        d = HH( d,a,b,c, M[12], S3[1], K[45] )         #46
        c = HH( c,d,a,b, M[15], S3[2], K[46] )         #47
        b = HH( b,c,d,a, M[2], S3[3], K[47] )          #48

        # Round 4
        a = II( a,b,c,d, M[0], S4[0], K[48] )          #49
        d = II( d,a,b,c, M[7], S4[1], K[49] )          #50
        c = II( c,d,a,b, M[14], S4[2], K[50] )         #51
        b = II( b,c,d,a, M[5], S4[3], K[51] )          #52
        a = II( a,b,c,d, M[12], S4[0], K[52] )         #53
        d = II( d,a,b,c, M[3], S4[1], K[53] )          #54
        c = II( c,d,a,b, M[10], S4[2], K[54] )         #55
        b = II( b,c,d,a, M[1], S4[3], K[55] )          #56
        a = II( a,b,c,d, M[8], S4[0], K[56] )          #57
        d = II( d,a,b,c, M[15], S4[1], K[57] )         #58
        c = II( c,d,a,b, M[6], S4[2], K[58] )          #59
        b = II( b,c,d,a, M[13], S4[3], K[59] )         #60
        a = II( a,b,c,d, M[4], S4[0], K[60] )          #61
        d = II( d,a,b,c, M[11], S4[1], K[61] )         #62
        c = II( c,d,a,b, M[2], S4[2], K[62] )          #63
        b = II( b,c,d,a, M[9], S4[3], K[63] )          #64

        # Add this hash to the result
        A = (A + a) % (2**32)
        B = (B + b) % (2**32)
        C = (C + c) % (2**32)
        D = (D + d) % (2**32)

    result = convertToLittleHex(A) + convertToLittleHex(B) + convertToLittleHex(C) + convertToLittleHex(D)
    return result
 
if __name__ == "__main__":
    # Argument Parser
    parser = argparse.ArgumentParser(description='Get MD5 hash of file.')
    parser.add_argument('file', metavar='path',help='The file to be hashed')
    parser.add_argument('--verbose', help="print the acutal block being processed", action="store_true")
    args = parser.parse_args()

    # Our logger
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    fname = args.file
    if not os.path.exists(fname):
        logger.error("File does not exist.")
        exit()
    else:
        logger.info("Opening file {}".format(fname))
        to_hash = open(fname,"rb")
        data = to_hash.read()
        print(md5sum(data))
        to_hash.close()
