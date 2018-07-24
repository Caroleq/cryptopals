import base64, binascii

to_encrypt = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" 	#input string
get_binary = binascii.unhexlify(to_encrypt) 										#raw data
base64_encoded = base64.b64encode(get_binary) 										#encode to get raw data
print( base64_encoded)
