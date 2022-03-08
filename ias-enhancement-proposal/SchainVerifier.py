#!/usr/bin/python3

import os
import sys
import json

import datetime
from collections import OrderedDict
from tkinter import E

import hmac
import hashlib
from ecdsa import VerifyingKey
from ecdsa.util import sigdecode_der

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
LENGTH_OF_MANUFACTURER_SIGNATURE = 72

BASE128_MAX_BYTES = 4 #number of recursions we are willing to undertake in order to identify section length header

HMAC_HEADER_LENGTH = 2
HMAC_BYTE_LENGTH = 8

###########
# CLASSES #
###########


#############
# FUNCTIONS #
#############

########################
# verifySchain
########################
#
# 
#
#
#  
def verifySchain(baseDir, schainPath):
	#startTime = datetime.datetime.now()
	sharedSecretsFilePath = os.path.join(baseDir, 'input/shared_secrets/shared_secrets.json')
	manufacturerPublicKeyPath = os.path.join(baseDir, f'input/keys/ecdsa/manufacturer/{PUBLIC_KEY_FILE_NAME}')

	partnerToSecretDict = loadPartnerSharedSecrets(sharedSecretsFilePath)
	protobufBytes, schainObject = loadProtobufSchain(schainPath)
	manufacturerPublicKey = loadManufacturerPublicKey(manufacturerPublicKeyPath)

	

	verifyHmacs(partnerToSecretDict, schainObject, protobufBytes)	

	verifyDeviceSignature(schainObject)

	verifyDeviceCertificate(manufacturerPublicKey, schainObject, protobufBytes)

	#endTime = datetime.datetime.now()
	#timeDiff = (endTime - startTime).total_seconds() * 1000
	#print(f'Check ran in {timeDiff} milliseconds')

def loadPartnerSharedSecrets(sharedSecretsFilePath):
	# retrieve shared secrets for each partner
	with open(sharedSecretsFilePath, 'r') as readHandle:
		sharedSecretsJson = json.load(readHandle)
	
	return sharedSecretsJson['shared_secrets']['partners_to_verifiers']

def loadProtobufSchain(schainPath):
	schainObject = schain_pb2.SchainMain()

	protobufBytes = None
	
	with open(schainPath, 'rb') as readHandle:
		protobufBytes = readHandle.read()
		schainObject.ParseFromString(protobufBytes)

	return protobufBytes, schainObject
	
def loadManufacturerPublicKey(manufacturerPublicKeyPath):
	# manufacturer public key should actually be obtained from the link included in the signed 'certificate'
	# in this demonstration, we will just pull it from file

	with open(manufacturerPublicKeyPath, 'r') as readHandle:
		manufacturerPublicKey = VerifyingKey.from_pem(readHandle.read())

	return manufacturerPublicKey

def verifyHmacs(partnerToSecretDict, schainObject, protobufBytes):
	# retrieve starting offets and lengths for schain blocks
	sectionStartLengthList = findNodeSectionStartsInProtobuf(protobufBytes)
	#print(sectionStartLengthList)


	# retrieve shared secrets for each supply chain partner
	partnerToSharedSecretDict = retrieveSchainPartnersFromSchain(schainObject)

	retrieveSharedSecretsForPartners(partnerToSecretDict, partnerToSharedSecretDict)
	#print(partnerToSharedSecretDict)

	# starting with the last block, remove signature and check hmac
	partnerToSecretList = list(partnerToSharedSecretDict.items())
	for nodeIndex in range(0, len(sectionStartLengthList)):
		nodeBlockOffset, headerEndIndex, sectionLength = sectionStartLengthList[nodeIndex]
		
		# retrieve and remove hmac from byte array
		storedHmac, protobufBytes = popHmac(protobufBytes, nodeBlockOffset, headerEndIndex, sectionLength)

		#print(protobufBytes.hex())
		#print(partnerToSecretList[nodeIndex])
		# verify hmac
		hmacHash = hmac.digest(bytes.fromhex(partnerToSecretList[nodeIndex][1]), protobufBytes, hashlib.sha256)
		#print(storedHmac.hex(), hmacHash.hex())
		if storedHmac in hmacHash:
			print(f'HMAC check success for {partnerToSecretList[nodeIndex][0]} ({storedHmac.hex()})\n')
		else:
			print(f'HMAC check failed for {partnerToSecretList[nodeIndex][0]}\n')

		# remove this node from protobuf
		protobufBytes = popNode(protobufBytes, nodeBlockOffset)


def findNodeSectionStartsInProtobuf(protobufBytes):
	sectionStartLengthList = [] #reverse order starting from last node

	#parse from back of byte array, and look for hex '32'
	sectionEndIndex = len(protobufBytes)
	for index in range(len(protobufBytes) - 1, -1, -1):
		if protobufBytes[index] == 0x32:
			sectionLength, headerEndIndex = retrieveSectionLength(protobufBytes, index, sectionEndIndex, True)
			if sectionLength:
				sectionStartLengthList.append((index, headerEndIndex, sectionLength))
				sectionEndIndex = index

	return sectionStartLengthList
	
def retrieveSectionLength(protobufBytes, index, sectionEndIndex, isSectionLengthLookup):
	
	#retrieve potential section length header
	sectionLength, headerEndIndex = base128custom.getHeaderLengthAndEndOffset(protobufBytes, index + 1, sectionEndIndex)

	#bounds check
	if isSectionLengthLookup and (sectionLength == sectionEndIndex - headerEndIndex) and (protobufBytes[headerEndIndex] == 10 or protobufBytes[headerEndIndex] == 1): #\x0a or \x01
		return sectionLength, headerEndIndex
	else:
		return None, headerEndIndex



def retrieveSchainPartnersFromSchain(schainObject):
	partnerToSharedSecretDict = OrderedDict()

	#iterate over each node starting from newest
	#extract each partner name
	for index in range(0, len(schainObject.schain.nodes)):
		currentNode = schainObject.schain.nodes.pop()
		partnerToSharedSecretDict[currentNode.asi] = None

	return partnerToSharedSecretDict


def retrieveSharedSecretsForPartners(partnerToSecretDict, partnerToSharedSecretDict):
	
	for partner in list(partnerToSharedSecretDict.keys()):
		try:
			partnerToSharedSecretDict[partner] = partnerToSecretDict[partner]
		except KeyError as e:
			print(f'Failed to find shared secret for {partner} in input/shared_secrets/shared_secrets.json')
			print(e)
			exit(2)



def popHmac(protobufBytes, nodeBlockOffset, headerEndIndex, sectionLength):
	lastOffset = len(protobufBytes)

	#find hmac section and remove
	hmacOffset = findHmacOffset(protobufBytes, nodeBlockOffset, lastOffset)
	if hmacOffset and hmacOffset + HMAC_HEADER_LENGTH + HMAC_BYTE_LENGTH < lastOffset:
		hmacBytes = protobufBytes[hmacOffset+ HMAC_HEADER_LENGTH:hmacOffset + HMAC_BYTE_LENGTH]
	else:
		print(f'Failed to find HMAC for section offset {nodeBlockOffset}')
		exit(1)

	shortenedProtobufBytes = protobufBytes[:hmacOffset] + protobufBytes[hmacOffset + HMAC_HEADER_LENGTH + HMAC_BYTE_LENGTH:lastOffset]

	#adjust protobuf byte array section header to compensate for removed hmac section
	newSectionLength = sectionLength - (HMAC_HEADER_LENGTH + HMAC_BYTE_LENGTH)
	lengthAsBase128Bytes = base128custom.convertToBase128(newSectionLength)
	#remove old length header, add new header
	newSectionHeaderProtobufBytes = shortenedProtobufBytes[:nodeBlockOffset + 1]
	for headerByte in lengthAsBase128Bytes:
		newSectionHeaderProtobufBytes += headerByte
	newSectionHeaderProtobufBytes += shortenedProtobufBytes[headerEndIndex:]
	
	#adjust protobuf general header at offset 0x1
	protobufLength, protobufLengthHeaderEndIndex = retrieveSectionLength(protobufBytes, 0, len(protobufBytes), False)
	
	newProtobufLength = len(newSectionHeaderProtobufBytes) - protobufLengthHeaderEndIndex #start length count from data section to end of protobuf
	#print(protobufLength, newProtobufLength)
	newProtobufLengthAsBase128Bytes = base128custom.convertToBase128(newProtobufLength)
	
	returnProtobuf = b'\x0A'
	for headerByte in newProtobufLengthAsBase128Bytes:
		returnProtobuf += headerByte
	returnProtobuf += newSectionHeaderProtobufBytes[protobufLengthHeaderEndIndex:]

	return hmacBytes, returnProtobuf

def findHmacOffset(protobufBytes, nodeBlockOffset, lastOffset):
	
	for index in range(nodeBlockOffset, lastOffset):
		if index + 2 < lastOffset and protobufBytes[index] == 0x0A and protobufBytes[index + 1] == 0x08:
			return index
			

def popNode(protobufBytes, nodeBlockOffset):
	#no need to adjust main length header, as this will be adjusted by the next call to the popHmac method
	return protobufBytes[:nodeBlockOffset]



def verifyDeviceSignature(schainObject):
	#extract device public key
	devicePublicKey = VerifyingKey.from_der(schainObject.schain.anon_cert.device_pub_key)
	

	#extract signature and plain text token from schainObject
	tokenSignature = schainObject.schain.token_signed
	tokenPlaintext = schainObject.schain.token_plaintext

	#verify token
	if devicePublicKey.verify(tokenSignature, bytes(tokenPlaintext, 'utf-8'), sigdecode=sigdecode_der,  hashfunc=HASH_STRENGTH):
		print('Token verified using device certificate\n')
	else:
		print('Token verification failed\n')


def verifyDeviceCertificate(manufacturerPublicKey, schainObject, protobufBytes):

	'''
	# re-generate anon cert 
	anonCertMain = anon_cert_pb2.AnonCertMain()
	anonCert = anonCertMain.anon_cert

	anonCert.device_pub_key = schainObject.schain.anon_cert.device_pub_key
	anonCert.device_id = schainObject.schain.anon_cert.device_id
	anonCert.issuer_cert_url = schainObject.schain.anon_cert.issuer_cert_url
	anonCert.expiration = schainObject.schain.anon_cert.expiration

	anonCertProtobufBytes = anonCert.SerializeToString()
	print(anonCertProtobufBytes.hex())
	'''

	# identify anon cert region and extract anon cert
	# look for 2A header, followed by length header
	sectionStart = None
	for byteIndex in range(0, len(protobufBytes)):
		
		if protobufBytes[byteIndex] == 42:#b'\x2a':
			#get section length
			sectionLength, headerEndIndex = base128custom.getHeaderLengthAndEndOffset(protobufBytes, byteIndex + 1, len(protobufBytes))

			#check if byte after potential anon cert section is another protobuf section
			if protobufBytes[sectionLength + headerEndIndex] == 50 or protobufBytes[headerEndIndex] == 42: #b'\x32' b'\x2a':
				sectionStart = byteIndex
				break
	
	if sectionStart:
		#remove current header and manufacturer signature block
		anonCertMinusSignatureEndIndex = sectionLength + headerEndIndex - LENGTH_OF_MANUFACTURER_SIGNATURE
		anonCertProtobufMinusHeader = protobufBytes[headerEndIndex: anonCertMinusSignatureEndIndex]
		
		#append header to anon cert protobuf
		anonCertProtobuf = appendProtobufHeader(anonCertProtobufMinusHeader)
		
		if manufacturerPublicKey.verify(schainObject.schain.anon_cert.manufacturer_signature, anonCertProtobuf, sigdecode=sigdecode_der,  hashfunc=HASH_STRENGTH):
			print('Manufacturer certificate verified\n')
		else:
			print('Manufacturer certificate failed check\n')
	else:
		print('Failed to find Anon cert section\n')
		exit(5)





def appendProtobufHeader(protobufMinusHeader):
        #append header to protobuf (which is strangely missing from SerializeToString method)
        protobufLength = len(protobufMinusHeader)
        lengthHeader = base128custom.convertToBase128(protobufLength)
        newProtobuf = b'\x0A'
        for headerByte in lengthHeader:
            newProtobuf += headerByte
        #print(type(newProtobuf))
        newProtobuf += protobufMinusHeader
        #print(newProtobuf.hex())
        return newProtobuf

########
# MAIN #
########

if __name__ == "__main__":

	if len(sys.argv) != 2:
		print("Please provide absolute path to file containing schain")
		exit(1)
	
	

	baseDir = os.path.dirname(os.path.realpath(__file__))
	schainPath = sys.argv[1]

	verifySchain(baseDir, schainPath)
	