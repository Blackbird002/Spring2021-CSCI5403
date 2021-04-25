import hashlib
import sys
import time
import logging

# Finds a First/Last 7 (FL7) partial collision in MD5

# Dictionary {key : value}
# {first7 + last7 : md5Hash}
slayerCandidates = {}
cycleCount = 0

def checkCandidatesforFL7(key):
    match = False
    if(len(slayerCandidates) > 0):
       if(key in slayerCandidates):
           match = True
           print("Found First/Last 7-Collision in md5")
           print(slayerCandidates.get(key))
    return match

def findFL7Collision(Text):
    logger.info("Finding FL7 collision... Working...")
    global cycleCount
    found = False
    hashKey = ""

    hash = hashlib.md5(Text).hexdigest()
    while(not found):
        hashKey = hash[0:7]
        hashKey += hash[25:32]
        if(checkCandidatesforFL7(hashKey)):
            print(hash)
            found = True
        else:
            #Add hash to Candidate list
            slayerCandidates[hashKey] = hash

            #Generate a new md5 hash from prior md5 hash result
            hash = hash.encode('utf-8')
            hash = hashlib.md5(hash).hexdigest()
            cycleCount += 1

if __name__ == "__main__":
    logger = logging.getLogger()
    handler = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s %(name)-12s %(levelname)-8s %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    startingText = " "

    if len(sys.argv) <= 1:
        logger.error("Missing string input argument")
    else:
        startingText = sys.argv[1]
        logger.info("Starting string is: {}".format(startingText))
        startingText = startingText.encode('utf-8')
        startTime = time.time()
        findFL7Collision(startingText)
        deltaT = time.time() - startTime
        logger.info("Elapsed Time: {:.2f} s".format(deltaT))
        logger.info("Total # of hash cycles: {}".format(cycleCount))
