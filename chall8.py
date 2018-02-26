import binascii

def detect_ECB(data):
	"""detects ECB encrypted string because (16 bytes length blocks)"""
	encrypted=[]
	for line in data:
		split=[line[i:i+16] for i in xrange(0, len(line),16)]
		j=0
		while j< len(split):	
			k=j+1
			while k<len(split):
				if split[j]==split[k]:				#if block is repeated, then it was probably encrypted in ecb mode
					encrypted.append(line)			#so we can add this line to the list and stop searching
					break
				k+=1
			if line in encrypted:
				break
			j+=1
	return encrypted


def main():
	data_f=open('8.txt')
	data_lines=data_f.readlines()	
	data=[]
	for line in data_lines:
		data.append(binascii.unhexlify(line.strip('\n')))
	e=detect_ECB(data)
	for elem in e:
		print binascii.hexlify(elem)
	data_f.close()


if __name__=="__main__":
	main()

