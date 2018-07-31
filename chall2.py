import binascii



def xor_hex(buffer1, buffer2):
    """
      Function takes two hex-encoded buffers of equal length and produces their xor value
    """
    if len(buffer1) != len(buffer2):
        raise Exception("Buffers should have equal length")

    binary1 = binascii.unhexlify(buffer1)
    binary2 = binascii.unhexlify(buffer2)

    xor_list = [ chr(val1^val2) for (val1, val2) in zip(binary1, binary2)]
    xor = ''.join(xor_list)
  
    return str(binascii.hexlify( bytes(''.join(xor_list), 'utf-8')))[2:-1]



def xor_bytes(buffer1, buffer2):
    """
        Function takes two byte-type objects of equal length and produces their xor value
    """
    if len(buffer1) != len(buffer2):
        raise Exception("Strings should have equal length")

    xor_result = [ val1^val2  for (val1, val2) in zip(buffer1, buffer2)]

    return bytes(xor_result) 





if __name__ == "__main__":
    buffer1 = '1c0111001f010100061a024b53535009181c'
    buffer2 = '686974207468652062756c6c277320657965'

    assert xor_hex(buffer1, buffer2) == '746865206b696420646f6e277420706c6179'


