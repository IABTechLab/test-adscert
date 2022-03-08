#!/usr/bin/python3


from bitarray import bitarray
from tkinter import E


###########
# GLOBALS #
###########

BASE128_MAX_BYTES = 4 #number of recursions we are willing to undertake in order to identify section length header

HMAC_HEADER_LENGTH = 2
HMAC_BYTE_LENGTH = 8

###########
# CLASSES #
###########


#############
# FUNCTIONS #
#############

def getHeaderLengthAndEndOffset(protobufBytes, nextIndex, sectionEndIndex):
	bitString, headerEndIndex = getNextByteIfBase128(protobufBytes, nextIndex, sectionEndIndex, 0)

	sectionLength = bitArrayToInt(bitString)
	return sectionLength, headerEndIndex


def getNextByteIfBase128(protobufBytes, nextIndex, sectionEndIndex, recursionIndex):
	if recursionIndex >= BASE128_MAX_BYTES:
		return bitarray(), sectionEndIndex

	if recursionIndex >= sectionEndIndex:
		return bitarray(), sectionEndIndex

	currentHeaderByte = protobufBytes[nextIndex]
	#print((currentHeaderByte).to_bytes(2, byteorder='big').hex())
	#if least significant bit is one, recurse and get next digit
	if (currentHeaderByte >> 7) & 0x01: #if least significant bit is 1
		priorBitstring, headerEndIndex = getNextByteIfBase128(protobufBytes, nextIndex + 1, sectionEndIndex, recursionIndex + 1)
		#remove LSB then convert to bit array
		return priorBitstring + convertByteToBitArray(currentHeaderByte & 0x7f), headerEndIndex
	else:
		return convertByteToBitArray(currentHeaderByte), nextIndex + 1

def convertByteToBitArray(headerByte):
	#convert byte to bit array (not using LSB)
	bitString = bitarray()

	for bitShiftIndex in range(6, -1, -1):
		bitString.append((headerByte >> bitShiftIndex) & 0x01)
	 
	# return 7 character bit array 
	return bitString

def bitArrayToInt(bitString):
	i = 0
	for bit in bitString:
		i = (i << 1) | bit

	return i


			
# from bitarray import bitarray
def convertToBase128(sectionLength):
	lengthBitArray = bitarray()
	lengthBitArray.frombytes((sectionLength).to_bytes(2, byteorder='big'))
	return(bitifyNext7SignificantBits(bitarray(lengthBitArray.to01().lstrip('0'))))

def bitifyNext7SignificantBits(lengthBitArray):
	byteArray = []
	if len(lengthBitArray) > 7:
		byteArray.append((bitarray('1') + lengthBitArray[-7:]).tobytes())
		byteArray += bitifyNext7SignificantBits(lengthBitArray[:-7])   
	else:
		while len(lengthBitArray) < 8:
			lengthBitArray.insert(0, 0)
		byteArray.append(lengthBitArray.tobytes())
	return byteArray

########
# MAIN #
########

