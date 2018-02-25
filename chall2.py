import binascii

#extract raw data
num1=binascii.unhexlify('1c0111001f010100061a024b53535009181c')
num2=binascii.unhexlify('686974207468652062756c6c277320657965')


out=""
index=0
#xor operation for whole number
while index<len(num1):
	out+=chr(ord(num1[index])^ord(num2[index]))
	index+=1
#hex encode
encoded=binascii.hexlify(out)
print encoded


