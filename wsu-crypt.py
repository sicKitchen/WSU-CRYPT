###################
# Spencer kitchen #
#    WSU-CRYPT    #
#    2/14/2017    #
###################


###########
# F table #
###########
ftable =   [[0xa3,0xd7,0x09,0x83,0xf8,0x48,0xf6,0xf4,0xb3,0x21,0x15,0x78,0x99,0xb1,0xaf,0xf9],
            [0xe7,0x2d,0x4d,0x8a,0xce,0x4c,0xca,0x2e,0x52,0x95,0xd9,0x1e,0x4e,0x38,0x44,0x28],
            [0x0a,0xdf,0x02,0xa0,0x17,0xf1,0x60,0x68,0x12,0xb7,0x7a,0xc3,0xe9,0xfa,0x3d,0x53],
            [0x96,0x84,0x6b,0xba,0xf2,0x63,0x9a,0x19,0x7c,0xae,0xe5,0xf5,0xf7,0x16,0x6a,0xa2],
            [0x39,0xb6,0x7b,0x0f,0xc1,0x93,0x81,0x1b,0xee,0xb4,0x1a,0xea,0xd0,0x91,0x2f,0xb8],
            [0x55,0xb9,0xda,0x85,0x3f,0x41,0xbf,0xe0,0x5a,0x58,0x80,0x5f,0x66,0x0b,0xd8,0x90],
            [0x35,0xd5,0xc0,0xa7,0x33,0x06,0x65,0x69,0x45,0x00,0x94,0x56,0x6d,0x98,0x9b,0x76],
            [0x97,0xfc,0xb2,0xc2,0xb0,0xfe,0xdb,0x20,0xe1,0xeb,0xd6,0xe4,0xdd,0x47,0x4a,0x1d],
            [0x42,0xed,0x9e,0x6e,0x49,0x3c,0xcd,0x43,0x27,0xd2,0x07,0xd4,0xde,0xc7,0x67,0x18],
            [0x89,0xcb,0x30,0x1f,0x8d,0xc6,0x8f,0xaa,0xc8,0x74,0xdc,0xc9,0x5d,0x5c,0x31,0xa4],
            [0x70,0x88,0x61,0x2c,0x9f,0x0d,0x2b,0x87,0x50,0x82,0x54,0x64,0x26,0x7d,0x03,0x40],
            [0x34,0x4b,0x1c,0x73,0xd1,0xc4,0xfd,0x3b,0xcc,0xfb,0x7f,0xab,0xe6,0x3e,0x5b,0xa5],
            [0xad,0x04,0x23,0x9c,0x14,0x51,0x22,0xf0,0x29,0x79,0x71,0x7e,0xff,0x8c,0x0e,0xe2],
            [0x0c,0xef,0xbc,0x72,0x75,0x6f,0x37,0xa1,0xec,0xd3,0x8e,0x62,0x8b,0x86,0x10,0xe8],
            [0x08,0x77,0x11,0xbe,0x92,0x4f,0x24,0xc5,0x32,0x36,0x9d,0xcf,0xf3,0xa6,0xbb,0xac],
            [0x5e,0x6c,0xa9,0x13,0x57,0x25,0xb5,0xe3,0xbd,0xa8,0x3a,0x01,0x05,0x59,0x2a,0x46]]


# pass it g and subkey before you perform xor. It is performed in the function
def Ftable(g, k):
    # k is in hex so convert to binary first
    k_bin = hex_to_bin(k, 8)
    # xor g & l together
    lookup = xor(g, k_bin, 8)

    # To look up in f table, we need to split lookup into 4 bit hex
    column = int(lookup[0:4], 2)
    row = int(lookup[4:], 2)

    # fetch the value from the ftable
    value = ftable[column][row]
    # value returned is in decimal, convert to hex
    value_hex = hex(value)[2:]
    # convert to binary
    value_bin = hex_to_bin(value_hex, 8)
    return value_bin


################
# Input/output #
################
# Open plaintext file
def get_text(file):
    fd = open(file, "r")
    encoded_plain_text = []         # holds encoded blocks from plaintext

    # Get the Ascii text from file plaintext.txt in 8 character blocks
    # 8 chars * 8 bits per char = 64 bits
    while True:   # read until end of file
        block = fd.read(8)
        if block == '':
            break
        # encode ascii into hex
        encoded_block = block.encode('hex')
        encoded_plain_text.append(encoded_block)
    return encoded_plain_text


# Open key file
def get_key(file):
    fd = open(file, "r")
    return fd.read()


#########################################
# Generate Encryption & Decryption keys #
#########################################
def gen_encrypt_keys(key_hex):
    # Holds all outputted keys
    keychain = []

    # convert hex key into binary key
    key_bin = hex_to_bin(key_hex, 64)

    index = 0
    while index < 192:
        # first do a left shift on binary key
        key_bin = shift_left(key_bin)

        # then we convert the key into bytes
        key_byte = parse_binary(key_bin, 8)

        # funky math to figure out which byte to access
        # Since all k values are computed in the beginning,
        # this takes the round +1-3 into account
        choose_byte = (4 * (index / 12) + (index % 4)) % 8
        keychain.append(key_byte[choose_byte])
        index += 1
    return keychain


def gen_decrypt_keys(key_hex):
    # Holds all outputted keys
    keychain = [None] * 192

    # convert hex key into binary key
    key_bin = hex_to_bin(key_hex, 64)

    index = 0
    while index < 192:
        # we convert the key into bytes
        key_byte = parse_binary(key_bin, 8)
        # reverse the order
        key_byte.reverse()
        choose_byte = (4 * (index / 12) + (index % 4)) % 8
        place = (12 * (index / 12 + 1) - 1) - index % 12
        keychain[place] = key_byte[choose_byte]
        key_bin = shift_right(key_bin)
        index += 1
    return keychain


#####################
# Binary operations #
#####################
def hex_to_bin(hex, length):
    scale = 16  # equals to hexadecimal
    num_of_bits = length  # for padding 0 if doing only 4 bit hex
    return bin(int(hex, scale))[2:].zfill(num_of_bits)


def bin_to_hex(bin):
    return hex(int(bin, 2)).rstrip('L').lstrip('0x')


def parse_binary(binary, num_bits):
    start = 0      # start of byte
    end = 1        # end of byte
    i = 0
    binary_size = len(binary)  # how many bytes in bianary string
    bytes = []     # holds all bytes

    while i < binary_size/num_bits:
        # Nifty little slice feature of python
        bytes.append(binary[(num_bits*start):(num_bits*end)])
        i += 1
        start = i
        end = i + 1
    return bytes


def xor(word, key, length):
    output = []    # holds xor
    i = 0
    while i < length:
        if int(word[i]) + int(key[i]) == 0:
            output.append('0')
        elif int(word[i]) + int(key[i]) == 1:
            output.append('1')
        elif int(word[i]) + int(key[i]) == 2:
            output.append('0')
        i += 1
    output = ''.join(output)
    return output


def shift_left(binary):
    bin_len = len(binary)
    array_bin = list(binary)

    # handle high bit special case
    # first bit moves to last bit
    save = array_bin[0]
    i = 0
    while i < bin_len:
        # if last bit, put first bit there
        if i == bin_len - 1:
            array_bin[i] = save
            i += 1
        else:
            next = array_bin[i+1]
            array_bin[i] = next
            i += 1
    # Combine array back into string
    output = "".join(array_bin)
    return output


def shift_right(binary):
    bin_len = len(binary)
    array_bin = list(binary)
    # save last bit
    save = array_bin[bin_len -1]

    i = bin_len - 1
    while i >= 0:
        # if first bit put save there
        if i == 0:
            array_bin[i] = save
            i -= 1
        else:
            prev = array_bin[i-1]
            array_bin[i] = prev
            i -= 1
    # combine array back into string
    output = "".join(array_bin)
    return output


##################
# Whitening Step #
##################
def whiten(plaintext, master_key):
    r_values = []     # holds created r values

    # convert plain text and key into binary
    text_bin = hex_to_bin(plaintext, 64)
    key_bin = hex_to_bin(master_key, 64)

    # divide plaintext into 4 words
    # w0,w1,w2,w3
    words = parse_binary(text_bin, 16)

    # divide key into 4 keys
    # k0,k1,k2,k3
    keys = parse_binary(key_bin, 16)

    r_values.append(xor(words[0], keys[0], 16))  # R0 = W0 xor K0
    r_values.append(xor(words[1], keys[1], 16))  # R1 = W1 xor K1
    r_values.append(xor(words[2], keys[2], 16))  # R2 = W2 xor K2
    r_values.append(xor(words[3], keys[3], 16))  # R3 = W# xor K3

    return r_values


##############
# F function #
##############
def F (r0, r1, round, subkeys):
    # first we get t's from G()
    t0 = G(r0, round, subkeys[round][0], subkeys[round][1], subkeys[round][2], subkeys[round][3])
    t1 = G(r1, round, subkeys[round][4], subkeys[round][5], subkeys[round][6], subkeys[round][7])

    print ("t0:" + bin_to_hex(t0) + " t1:" + bin_to_hex(t1))

    # turn subkeys from hex to binary
    sub1 = hex_to_bin(subkeys[round][8], 8)
    sub2 = hex_to_bin(subkeys[round][9], 8)
    cat = sub1 + sub2

    # print "cat: " + cat
    # compute f0, is in decimal
    f0 = (int(t0, 2) + 2*int(t1, 2) + int(cat, 2)) % 2**16
    # convert to hex
    f0_hex = hex(f0)[2:]

    # turn subkeys from hex to binary
    sub1 = hex_to_bin(subkeys[round][10], 8)
    sub2 = hex_to_bin(subkeys[round][11], 8)
    cat = sub1 + sub2

    # compute f0, is in decimal
    f1 = (2 * int(t0, 2) + int(t1, 2) + int(cat, 2)) % 2 ** 16
    # convert to hex
    f1_hex = hex(f1)[2:]

    print("f0:" + f0_hex + " f1:" + f1_hex)
    return f0_hex, f1_hex


##############
# G function #
##############
def G(w, round, subkey1, subkey2, subkey3, subkey4):
    g = []  # holds g table 0-5 (6 g's)
    g.append(w[0:8])                                # g[0] left 8 bits of w
    g.append(w[8:])                                 # g[1] right 8 bits of w
    g.append(xor(g[0], Ftable(g[1], subkey1), 8))   # g[2] ftable(g[1] xor subkey1) xor g[0]
    g.append(xor(g[1], Ftable(g[2], subkey2), 8))   # g[3] ftable(g[2] xor subkey2) xor g[1]
    g.append(xor(g[2], Ftable(g[3], subkey3), 8))   # g[4] ftable(g[3] xor subkey3) xor g[2]
    g.append(xor(g[3], Ftable(g[4], subkey4), 8))   # g[5] ftable(g[4] xor subkey4) xor g[3]

    print("g1:" + bin_to_hex(g[0]) + " g2:" + bin_to_hex(g[1]) + " g3:" + bin_to_hex(g[2]) + " g4:" + bin_to_hex(g[3])
          + " g5:" + bin_to_hex(g[4]) + " g6:" + bin_to_hex(g[5]))

    output = g[4] + g[5]
    return output


####################
# Encrypt function #
####################
def encrypt(plain_text, key, subkeys):
    round = 0
    print ("Encoded plain text: " + plain_text + " Key: " + key)

    # perform whitening step
    r_values = whiten(plain_text, key)
    r_values_hex = ''.join(r_values)  # join r values into 64 bit string
    r_values_hex = bin_to_hex(r_values_hex)  # convert to hex

    print ("After Whiting: " + r_values_hex)

    # Start loop of 16 rounds
    while round < 16:
        print ("This is round " + str(round))

        # Compute function F()
        f_values = F(r_values[0], r_values[1], round, subkeys)

        # Compute r2 xor f0 then shift right
        f0 = hex_to_bin(f_values[0], 16)
        save_r0 = r_values[0]
        r_values[0] = shift_right(xor(r_values[2], f0, 16))

        # compute r3 shifted left xor f1
        f1 = hex_to_bin(f_values[1], 16)
        save_r1 = r_values[1]
        r_values[1] = xor(shift_left(r_values[3]), f1, 16)

        r_values[2] = save_r0
        r_values[3] = save_r1

        r_values_hex = ''.join(r_values)  # join r values into 64 bit string
        r_values_hex = bin_to_hex(r_values_hex)  # convert to hex
        print ("After one round: " + r_values_hex)
        print ''
        round += 1

    # Undo last round to get the encrypted text
    y = []  # Holds swapped r values
    y.append(r_values[2])  # y0
    y.append(r_values[3])  # y0
    y.append(r_values[0])  # y0
    y.append(r_values[1])  # y0

    encrypt = ''.join(y)  # join r values into 64 bit string
    encrypt = bin_to_hex(encrypt)  # convert to hex

    # perform whitening step one last time
    encrypt = whiten(encrypt, key)
    encrypt = ''.join(encrypt)  # join back into 64 bit string
    encrypt = bin_to_hex(encrypt)  # convert to hex
    print ("Encrypted Block: " + encrypt)
    return encrypt


def decrypt(plain_text, key, subkeys):
    round = 0
    print ("Encrypted text: " + plain_text + " Key: " + key)

    # perform whitening step
    r_values = whiten(plain_text, key)
    r_values_hex = ''.join(r_values)  # join r values into 64 bit string
    r_values_hex = bin_to_hex(r_values_hex)  # convert to hex

    print ("After Whiting: " + r_values_hex)

    # Start loop of 16 rounds
    while round < 16:
        print ("This is round " + str(round))

        # Compute function F()
        f_values = F(r_values[0], r_values[1], round, subkeys)

        # rotate R2 left by 1 bit to get R2' and compute R2' xor F0.
        f0 = hex_to_bin(f_values[0], 16)        # get f0
        save_r0 = r_values[0]
        r_values[0] = xor(shift_left(r_values[2]), f0, 16)

        # compute R3 xor F1 and then rotate this value right by 1 bit
        f1 = hex_to_bin(f_values[1], 16)        # fet f1
        save_r1 = r_values[1]
        r_values[1] = shift_right(xor(r_values[3], f1, 16))

        r_values[2] = save_r0
        r_values[3] = save_r1

        r_values_hex = ''.join(r_values)  # join r values into 64 bit string
        r_values_hex = bin_to_hex(r_values_hex)  # convert to hex
        print ("After one round: " + r_values_hex)
        print ''
        round += 1

    # Undo last round to get the decrypted text
    y = []  # Holds swapped r values
    y.append(r_values[2])  # y0
    y.append(r_values[3])  # y0
    y.append(r_values[0])  # y0
    y.append(r_values[1])  # y0

    decrypt = ''.join(y)  # join r values into 64 bit string
    decrypt = bin_to_hex(decrypt)  # convert to hex

    # perform whitening step one last time
    decrypt = whiten(decrypt, key)
    decrypt = ''.join(decrypt)  # join back into 64 bit string
    decrypt = bin_to_hex(decrypt)  # convert to hex
    print ("Decrypted Block: " + decrypt)
    return decrypt


#########################
# ====== MAIN ========= #
#########################
if __name__ == "__main__":
    # Get the key from key.txt
    key = get_key("key.txt")

    # Generate all 192 encryption keys (1...191)
    encryptKeys = gen_encrypt_keys(key)

    # Generate all 192 decryption keys (1...191)
    decryptKeys = gen_decrypt_keys(key)

    # turn each encrypt key to a hex and build the table
    subkeys_encrypt = [[0 for x in range(12)] for y in range(16)]  # holds encrypt subkeys
    i = 0
    for row in range(16):
        for column in range(12):
            subkeys_encrypt[row][column] = bin_to_hex(encryptKeys[i])
            i += 1

    # turn each decrypt key to a hex and build the table
    subkeys_decrypt = [[0 for x in range(12)] for y in range(16)]  # holds encrypt subkeys
    i = 0
    for row in range(16):
        for column in range(12):
            subkeys_decrypt[row][column] = bin_to_hex(decryptKeys[i])
            i += 1

    print ("Generated Encrypt Sub Keys:")
    print ('\n'.join('{}:{}'.format(*k) for k in enumerate(subkeys_encrypt)))
    print
    print ("Generated Decrypt Sub Keys:")
    print ('\n'.join('{}:{}'.format(*k) for k in enumerate(subkeys_decrypt)))

    # Get the encoded plaintext file
    plain_text = get_text("plaintext.txt")          # comment out to run long text
    # plain_text = get_text("plaintext-long.txt")   # uncomment to run long text

    # encrypted_text is the total output of encrypted blocks
    # decrypt for decrypted blocks
    encrypted_text = []
    decrypted_text = []

    # feed the plaintext file into the encrypt function block at a time
    count = 1
    for block in plain_text:
        print "=============================== ENCRYPT ===================================="
        print ("Block " + str(count) + " of " + str(len(plain_text)))
        print ("Plain text: " + block.decode('hex'))
        # encrypt
        encrypted_text.append(encrypt(block, key, subkeys_encrypt))
        count += 1

    # Write the Encrypted text to file output.txt
    fd = open("output.txt", "w")
    fd.write("ENCRYPTED FULL TEXT:\n\n")
    fd.write(''.join(encrypted_text))
    fd.write("\n\n")

    # decrypt the encrypted_block
    count = 1
    for block in encrypted_text:
        print"============================== DECRYPT ==================================="
        print ("Block " + str(count) + " of " + str(len(encrypted_text)))
        # decrypt
        decrypted_text.append(decrypt(block, key, subkeys_decrypt))
        count += 1

    # print encrypted text to console
    print
    print ("ENCRYPTED TEXT")
    print ''.join(encrypted_text)

    # Print decrypted text to console
    print
    print ("DECRYPTED TEXT")
    decode = ''.join(decrypted_text)
    if len(decode) % 2 != 0:
        decode += '0'
        print decode.decode('hex')
    else:
        print decode.decode('hex')


    # Write the decrypted text to file output.txt
    fd.write("DECRYPTED FULL TEXT:\n\n")
    fd.write(decode.decode('hex'))
    fd.write("\n")
