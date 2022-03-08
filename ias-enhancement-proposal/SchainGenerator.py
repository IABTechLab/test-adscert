#!/usr/bin/python3

import os
import sys
import json
import time
import random
import string
from urllib.parse import urlparse
from urllib.parse import parse_qs

import hmac
import hashlib
import binascii
import base64
import brotli
from ecdsa import NIST256p
from ecdsa import SigningKey, VerifyingKey
from ecdsa.util import sigencode_der
from Crypto import Random
from Crypto.Cipher import AES

from pprint import pprint

# custom libraries
import base128custom

# protobuf libraries
import schain_pb2
import anon_cert_pb2



###########
# GLOBALS #
###########

PRIVATE_KEY_FILE_NAME = 'secp256r1_private_key.pem'
PUBLIC_KEY_FILE_NAME = 'secp256r1_public_key.pem'

HASH_STRENGTH = hashlib.sha256

CERTIFICATE_LIFE_NANOSECONDS = 7200000000000 # 2 hours

NONCE_LENGTH = 10
HMAC_CURTAIL_LENGTH = 8 #8 bytes

BROTLI_COMPRESSION_QUALITY = 11 #0 - 11. 11 is highest compression

REQUIRED_NODE_FIELDS = [
    'asi',
    'sid',
    'hp'
]

OPTIONAL_NODE_FIELDS = [
    'privacy_block',
    'next_hop',
    'recipient_verifiers'
]


###########
# CLASSES #
###########
# https://stackoverflow.com/questions/12524994/encrypt-decrypt-using-pycrypto-aes-256
class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        self.key = key #hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.urlsafe_b64encode(iv + cipher.encrypt(raw))
    '''
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')
    '''
    def _pad(self, s):
        return s + bytes((self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs), 'utf-8')

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


class Schain:
    def __init__(self, schainJson, tokenPlaintext, tokenSigned, anonCertObject):
        # dont append nodes here
        try:
            
            schain = schainJson['schain']
            self.anonCert = anonCertObject

            #generate JSON versin of self
            self.toJsonObject = {}
            self.toJsonObject['complete'] = schain['complete']
            self.toJsonObject['ver'] = schain['ver']
            self.toJsonObject['token_plaintext'] = tokenPlaintext
            self.toJsonObject['token_signed'] = base64.b64encode(tokenSigned).decode('utf-8')
            self.toJsonObject['anon_cert'] = {}
            self.toJsonObject['anon_cert']['issuer_signature'] = base64.b64encode(self.anonCert.issuerSignature).decode('utf-8')
            self.toJsonObject['anon_cert']['device_pub_key'] = base64.b64encode(self.anonCert.devicePubKey).decode('utf-8')
            self.toJsonObject['anon_cert']['device_id'] = self.anonCert.deviceId
            self.toJsonObject['anon_cert']['issuer_cert_url'] = self.anonCert.issuerCertUrl
            self.toJsonObject['anon_cert']['expiration'] = self.anonCert.expiration
            self.toJsonObject['nodes'] = []

            #generate protobuf of self
            schainMain = schain_pb2.SchainMain()
            self.protobuf = schainMain.schain
            self.protobuf.complete = schain['complete']
            self.protobuf.token_plaintext = tokenPlaintext
            self.protobuf.token_signed = tokenSigned
            self.protobuf.anon_cert.device_pub_key = self.anonCert.devicePubKey
            self.protobuf.anon_cert.device_id = self.anonCert.deviceId
            self.protobuf.anon_cert.issuer_cert_url = self.anonCert.issuerCertUrl
            self.protobuf.anon_cert.expiration = self.anonCert.expiration
            self.protobuf.anon_cert.manufacturer_signature = self.anonCert.issuerSignature


        except KeyError as e:
            print("Missing Anonymous Certificate field")
            print(e)
            exit(3)



        


    # for each provided partner node, copy fields, protobuf, then HMAC
    def appendNodeProtobufHmac(self, nodeObject, iterationNum, partnerSharedSecret, potentialVerifiers):
        # required fields
        nodeObjectJson = {}
        protobufNode = self.protobuf.nodes.add()
        try:
            
            for field in REQUIRED_NODE_FIELDS:
                nodeObjectJson[field] = nodeObject[field]

            if potentialVerifiers: # only first node should have potential_verifiers list
                nodeObjectJson['potential_verifiers'] = potentialVerifiers
                protobufNode.potential_verifiers.extend(potentialVerifiers)
                
            protobufNode.sid = nodeObject['sid']
            protobufNode.hp = nodeObject['hp']
            protobufNode.asi = nodeObject['asi']

        except KeyError as e:
            print("Node missing critical field")
            print(e)
            exit(4)

        # optional fields
        try:
            for field in OPTIONAL_NODE_FIELDS:
                nodeObjectJson[field] = nodeObject[field]
        except KeyError as e:
            pass

        self.toJsonObject['nodes'].append(nodeObjectJson)
        #print(nodeObject)
        if 'next_hop' in nodeObject:
            protobufNode.next_hop = nodeObject['next_hop'] 
        if 'recipient_verifiers' in nodeObject:
            protobufNode.recipient_verifiers.extend(nodeObject['recipient_verifiers']) 

        #generate HMAC
        hmacHash = hmac.digest(bytes.fromhex(partnerSharedSecret), self.appendProtobufHeaderReturnBytes(), hashlib.sha256)
        
        #append HMAC hash to this node
        protobufNode.hmac = hmacHash[:HMAC_CURTAIL_LENGTH]
        nodeObjectJson['hmac'] = base64.b64encode(protobufNode.hmac).decode('utf-8')

    def appendProtobufHeaderReturnBytes(self):
        #append header to protobuf (which is strangely missing from SerializeToString method)
        protobufBytes = self.protobuf.SerializeToString()
        protobufLength = len(protobufBytes)
        lengthHeader = base128custom.convertToBase128(protobufLength)
        newProtobuf = b'\x0A'
        for headerByte in lengthHeader:
            newProtobuf += headerByte
        #print(type(newProtobuf))
        newProtobuf += protobufBytes
        #print(newProtobuf.hex())
        return newProtobuf

    def compressFinalProtobuf(self):
        return brotli.compress(self.appendProtobufHeaderReturnBytes(), quality=BROTLI_COMPRESSION_QUALITY)
        



class AnonCert:
    def __init__(self, anonCertJson, devicePublicKey):
        try:
            anonCert = anonCertJson['anon_cert']
            self.deviceId = anonCert['device_id']
            self.issuerCertUrl = anonCert['issuer_cert_url']
            self.devicePubKey = devicePublicKey.to_der()
        except KeyError as e:
            print("Missing Anonymous Certificate field")
            print(e)
            exit(3)

    def protobufSerializeAndSign(self, currentTimestamp, manufacturerPrivateKey):
        self.expiration = currentTimestamp + CERTIFICATE_LIFE_NANOSECONDS
        self.anonCertMain = anon_cert_pb2.AnonCertMain()
        anonCert = self.anonCertMain.anon_cert

        anonCert.device_pub_key = self.devicePubKey
        anonCert.device_id = self.deviceId
        anonCert.issuer_cert_url = self.issuerCertUrl
        anonCert.expiration = self.expiration

        # digitally sign protobuf data
        anonCertProtobufBytes = self.anonCertMain.SerializeToString()
        print(anonCertProtobufBytes.hex())
        #self.issuerSignature = manufacturerPrivateKey.generate(curve=NIST256p).sign(anonCertMain.SerializeToString(), sigencode=sigencode_der)
        self.issuerSignature =  manufacturerPrivateKey.sign(anonCertProtobufBytes, sigencode=sigencode_der, hashfunc=HASH_STRENGTH)
        #print(anonCertMain.SerializeToString())
        #print(self.issuerSignature)
        #anonCert.manufacturer_signature = self.issuerSignature
        #print(self.anonCertMain.SerializeToString().hex())

#############
# FUNCTIONS #
#############

########################
# generateAnonCertObject
########################
#
# Uses device public key and manufacturer private key to generate anonymous certificate protobuf object
#
#
#  
def generateAnonCertObject(currentTimestamp, deviceKeyDir, manufacturerKeyDir, inputAnonCertJsonPath):

    # load in keys
    # device public key
    devicePublicKey = None
    manufacturerPrivateKey = None
    with open(os.path.join(deviceKeyDir, PUBLIC_KEY_FILE_NAME), 'r') as readHandle:
        devicePublicKey = VerifyingKey.from_pem(readHandle.read())
    with open(os.path.join(manufacturerKeyDir, PRIVATE_KEY_FILE_NAME), 'r') as readHandle:
        manufacturerPrivateKey = SigningKey.from_pem(readHandle.read())

    # load anon cert fields
    anonCertJson = loadInUserJson(inputAnonCertJsonPath) 

    # construct anon cert object for protobuf
    anonCertObject = AnonCert(anonCertJson, devicePublicKey)
    anonCertObject.protobufSerializeAndSign(currentTimestamp, manufacturerPrivateKey)

    return anonCertObject


def generateNonce(nonceLength):
    lettersAndNumbers = string.ascii_lowercase + '012345679'
    return ''.join(random.choice(lettersAndNumbers) for i in range(nonceLength))


def digitallySignChallenge(tokenPlaintext, deviceKeyDir):
    with open(os.path.join(deviceKeyDir, PRIVATE_KEY_FILE_NAME), 'r') as readHandle:
        devicePrivateKey = SigningKey.from_pem(readHandle.read())
        #return devicePrivateKey.generate(curve=NIST256p).sign(bytes(tokenPlaintext, 'utf-8'), sigencode=sigencode_der, hashfunc=HASH_STRENGTH)
        return devicePrivateKey.sign(bytes(tokenPlaintext, 'utf-8'), sigencode=sigencode_der, hashfunc=HASH_STRENGTH)

def loadInUserJson(inputJsonPath):

    userJson = None
    with open(inputJsonPath, 'r') as readHandle:
        try:
            userJson = json.load(readHandle)
        except ValueError as e:
            print("Failure to load JSON. Please check formatting.")
            print(e)
            exit(2)

    return userJson
        


########################
# generateSchain
########################
#
# Takes user generated schain data from input/input_json/* and generates anonymous certificate, signed token, and HMACs for each supply chain node
# Outputs populated schain JSON into output/json
# Compresses schain (minus privacy blocks) with brotli and base64 encodes. Output placed in output/brotli
#
# RETURN 
#       array - challenge pixels
#       map - string macro name : macro value
#       map - (final bidder to verfier) : shared secret
def generateSchain(baseDir, bidIdentifier):

    challengePixelMacrosDict = {}
    challengePixelMacrosDict['bid_id'] = bidIdentifier

    currentTimestamp = time.time_ns()

    deviceKeyDir = os.path.join(baseDir, 'input/keys/ecdsa/device/')
    manufacturerKeyDir = os.path.join(baseDir, 'input/keys/ecdsa/manufacturer/')
    inputSchainJsonPath = os.path.join(baseDir, 'input/input_json/schain.json')
    inputAnonCertJsonPath = os.path.join(baseDir, 'input/input_json/anon_cert.json')
    sharedSecretsJsonPath= os.path.join(baseDir, 'input/shared_secrets/shared_secrets.json')

    outputProtobufPath = os.path.join(baseDir, 'output/protobuf/output.payload')
    outputBrotliPath = os.path.join(baseDir, 'output/brotli/output.txt')
    outputJsonPath = os.path.join(baseDir, 'output/json/output.json')

    print(f"This script will generate ECDSA and HMAC signatures for your provide schain data (in '{inputSchainJsonPath}')")
    print("Output will be found in the 'output' directory in the formats JSON, Protobuf and Protobuf + Brotli compressed\n\n")

    #generate anonymous certificate
    anonCertObject = generateAnonCertObject(currentTimestamp, deviceKeyDir, manufacturerKeyDir, inputAnonCertJsonPath)

    #create digital signature of challenge nonce and other data
    contextNonce = generateNonce(NONCE_LENGTH)
    challengePixelMacrosDict['context_nonce'] = contextNonce
    tokenPlaintext = ':'.join([str(currentTimestamp), contextNonce, bidIdentifier])
    tokenSigned = digitallySignChallenge(tokenPlaintext, deviceKeyDir)


    #load in shared secrets
    sharedSecretsJson = loadInUserJson(sharedSecretsJsonPath)['shared_secrets']
    partnerToSecretDict = sharedSecretsJson['partners_to_verifiers']

    #load in user's input schain JSON
    schainJson = loadInUserJson(inputSchainJsonPath)
    
    if schainJson:

        schainObject = Schain(schainJson, tokenPlaintext, tokenSigned, anonCertObject)
        #pprint(vars(schainObject))
        #pprint(vars(anonCertObject))

        challengePixelList = []

        # loop through each node and generate hmac
        iterationNum = 0
        for nodeObject in schainJson['schain']['nodes']:
            if iterationNum == 0:
                potentialVerifiers = nodeObject['potential_verifiers']
                challengePixelMacrosDict['potential_verifiers'] = potentialVerifiers
                schainObject.appendNodeProtobufHmac(nodeObject, iterationNum, partnerToSecretDict[nodeObject['asi']], potentialVerifiers)
            else :
                schainObject.appendNodeProtobufHmac(nodeObject, iterationNum, partnerToSecretDict[nodeObject['asi']], None)

            if 'recipient_verifiers' in nodeObject:
                challengePixelList = challengePixelList + nodeObject['recipient_verifiers']
            iterationNum += 1


        # compress final protobuf encoded schain
        schainCompressed = schainObject.compressFinalProtobuf()
        challengePixelMacrosDict['schain'] = schainCompressed
        print(f'Schain compressed at Brotli quality level {BROTLI_COMPRESSION_QUALITY}. Length: ', len(schainCompressed))
        schainCompressedBase64 = base64.b64encode(schainCompressed)
        print(f'Base64 encoded compressed file stands at length: ', len(schainCompressedBase64))
        
        #write to file
        with open(outputProtobufPath, 'wb') as writeHandle:
            writeHandle.write(schainObject.appendProtobufHeaderReturnBytes())


        with open(outputBrotliPath, 'wb') as writeHandle:
            writeHandle.write(schainCompressedBase64)

        #pprint(schainObject.toJsonObject)
        with open(outputJsonPath, 'w') as writeHandle:
            json.dump(schainObject.toJsonObject, writeHandle)
        
        return challengePixelList, challengePixelMacrosDict, sharedSecretsJson['final_bidder_to_verifier']
        

########################
# populateChallengePixels
########################
#
# Takes list of challenge pixels
# Populates and digitally signs challenge pixel data
# Appends encrypted schain
#
# RETURN 
#       
def populateChallengePixels(baseDir, challengePixelList, challengePixelMacrosDict, verifierToSecretDict):

    challengePixelMacrosDict['timestamp'] = time.time_ns()
    populatedPixelsList = []

    finalBidderKeysDir = os.path.join(baseDir, 'input/keys/ecdsa/final_bidder')
    outputPixelsDir = os.path.join(baseDir, 'output/pixels/verifier_pixels.txt')

    for pixelUrl in challengePixelList:
        parsedUrl = urlparse(pixelUrl)

        challenge = None
        sharedSecret = None

        verifierDomain = parsedUrl.path.split('/')[0]

        # get verifier domain
        try:
            challenge = parse_qs(parsedUrl.query)['challenge'][0]
        except KeyError as e:
            print("Missing 'challenge' in query string for pixel", pixelUrl)
            print(e)
            exit(5)

        # get shared secret for this verifier
        try:
            sharedSecret = verifierToSecretDict[verifierDomain]
        except KeyError as e:
            print(f'No shared secret entry for parter {verifierDomain} in input/shared_secrets/shared_secrets.json')
            exit(6)

        # populate pixel macro using data from challengePixelMacrosDict
        pixelUrl = populateSignPixelMacros(parsedUrl.path, challenge, challengePixelMacrosDict, finalBidderKeysDir)

        encryptedBase64Schain = encryptSchain(challengePixelMacrosDict['schain'], binascii.unhexlify(sharedSecret)).decode('utf-8')

        pixelUrl += f'&schain={encryptedBase64Schain}'

        print(f'{pixelUrl}\n')
        populatedPixelsList.append(pixelUrl)

    with open(outputPixelsDir, 'w') as writeHandle:
        for pixel in populatedPixelsList:
            writeHandle.write(f'{pixel}\n')

def populateSignPixelMacros(pixelDomainPath, challenge, challengePixelMacrosDict, finalBidderKeysDir):
    timestamp = str(challengePixelMacrosDict['timestamp'])
    contextNonce = challengePixelMacrosDict['context_nonce']
    bidId = challengePixelMacrosDict['bid_id']

    #flatten array
    potentialVerifiers = ""
    for verifierDomain in challengePixelMacrosDict['potential_verifiers']:
        potentialVerifiers += f'{verifierDomain}_'
    potentialVerifiers = potentialVerifiers[:-1]

    challengeSignature = signPixelMacros(f'{timestamp}:{contextNonce}:{bidId}:{challenge}:{potentialVerifiers}', finalBidderKeysDir)
    base64Signature = base64.urlsafe_b64encode(challengeSignature).decode('utf-8')
    
    return f'https://{pixelDomainPath}?challenge={challenge}&context={contextNonce}&bid_id={bidId}&potential_verifiers={potentialVerifiers}&final_bidder=final_bidder.com&timestamp={timestamp}&bidders_signature={base64Signature}'


def signPixelMacros(plaintextData, finalBidderKeysDir):
    with open (os.path.join(finalBidderKeysDir, PRIVATE_KEY_FILE_NAME), 'r') as readHandle:
        finalBidderPrivatekey = SigningKey.from_pem(readHandle.read())
        #return finalBidderPrivatekey.generate(curve=NIST256p).sign(bytes(plaintextData, 'utf-8'), sigencode=sigencode_der, hashfunc=HASH_STRENGTH)
        return finalBidderPrivatekey.sign(bytes(plaintextData, 'utf-8'), sigencode=sigencode_der, hashfunc=HASH_STRENGTH)

def encryptSchain(compressedSchain, aesKey):
    aesObject = AESCipher(aesKey)
    return (aesObject.encrypt(compressedSchain))


########
# MAIN #
########

if __name__ == "__main__":

    if len(sys.argv) != 2:
        print("Please provide bid identifier (any string value)")
        exit(1)
    


    baseDir = os.path.dirname(os.path.realpath(__file__))
    bidIdentifier = sys.argv[1]

    challengePixelList, schainCompressed, verifierToSecretDict = generateSchain(baseDir, bidIdentifier)

    if len(challengePixelList) != 0:
        populateChallengePixels(baseDir, challengePixelList, schainCompressed, verifierToSecretDict)
    