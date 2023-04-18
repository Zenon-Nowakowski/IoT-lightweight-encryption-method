#SBOX and SBOX_INVERSE are arrays which map hex values for encrpytion and decryption
SBOX = {
    0x0: 0xC,
    0x1: 0x5,
    0x2: 0x6,
    0x3: 0xB,
    0x4: 0x9,
    0x5: 0x0,
    0x6: 0xA,
    0x7: 0xD,
    0x8: 0x3,
    0x9: 0xE,
    0xA: 0xF,
    0xB: 0x8,
    0xC: 0x4,
    0xD: 0x7,
    0xE: 0x1,
    0xF: 0x2
    }
SBOX_INVERSE = {
    0x0: 0x5,
    0x1: 0xE,
    0x2: 0xF,
    0x3: 0x8,
    0x4: 0xC,
    0x5: 0x1,
    0x6: 0x2,
    0x7: 0xD,
    0x8: 0xB,
    0x9: 0x4,
    0xA: 0x6,
    0xB: 0x3,
    0xC: 0x0,
    0xD: 0x7,
    0xE: 0x9,
    0xF: 0xA
}
pTable = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51, 4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55, 8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59, 12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]

def pLayer(state, pTable):
    # Convert the state to binary
    state_binary = bin(int(state, 16))[2:].zfill(64)
    # Define output as this cannot be defined during execute
    p_layer_output = ""
    # Loop through the permutation table and apply it to the state
    for i in pTable:
        p_layer_output += state_binary[i]
    # Convert back to hex
    p_layer_state = hex(int(p_layer_output, 2))
    # Return the permuted state
    return p_layer_state

def sBoxLayer(state, SBOX):
    #convert to binary
    state_binary = bin(int(state, 16))[2:].zfill(64)
    #define output as this cannot be defined during execute
    sbox_output = ""
    #for loop to loop through sections of the SBOX and apply them to 
    for i in range(0, 64, 4):
        #take a 4 bit section out of state binary 
        sec = state_binary[i:i+4]
        #find sbox section that alligns to binary we are attempting to convert 
        sbox_sec = bin(SBOX[int(sec, 2)])[2:].zfill(4)
        #combine sections
        sbox_output += sbox_sec
    #convert to hex
    sbox_state = hex(int(sbox_output, 2))
    #return completed state
    return sbox_state

def sBoxDecrypt(state, SBOX_INVERSE):
        #convert to binary
    state_binary = bin(int(state, 16))[2:].zfill(64)
    #define output as this cannot be define during execute
    sbox_output = ""
    #for loop to loop through sections of the SBOX and apply them to the state
    for i in range(0, 64, 4):
        #take a 4 bit section out of state binary 
        sec = state_binary[i:i+4]
        #find sbox section that alligns to binary we are attempting to convert 
        sbox_sec = bin(SBOX_INVERSE[int(sec, 2)])[2:].zfill(4)
        #combine sections
        sbox_output += sbox_sec
    #convert to hex
    sbox_state = hex(int(sbox_output, 2))
    #return completed state
    return sbox_state

#Performs a XOR operation between plaintext or "state" and the key k and return first part of cipher
def addRoundKey(plaintext, k):
    #convert plaintext and k into binary values 
    plaintext_binary = bin(int(plaintext, 16))[2:].zfill(64)
    k_binary = bin(int(k, 16))[2:].zfill(64)
    initial_state = ""
    #for loop for 64 bits creating initial state, combining the plaintext and key binaries 
    for i in range(64):
        initial_state += ''.join(str(int(plaintext_binary[i]) ^ int(k_binary[i])))
    #create final state, ie converted to hex from binary
    final_state = hex(int(initial_state, 2))
    return final_state

#function calls 
#plaintext and key
plaintext = "0x28B4D27B225F8BD8"
plaintext = plaintext.lower()
k = "0x0123456789ABCDEF"
k = k.lower()
print("Plaintext: " + plaintext)
print("Key: " + k)
#C1 is going to be plaintext plus key 
C1 = addRoundKey(plaintext, k)
print("C1: " + C1)
#C2 is C1 which utilizes SBOX
C2 = sBoxLayer(C1, SBOX)
print("C2: " + C2)
C3 = pLayer(C2, pTable)

#testing decryption
D1 = pLayer(C3, pTable)
D2 = sBoxDecrypt(C2, SBOX_INVERSE)
D3 = addRoundKey(D2, k)
if D3 == plaintext:
    print("Decryption Success!")

#PART 2
p = 47
q = 71
n = p * q
phi_n = (p - 1) * (q - 1)
e = 97
d = 1693 

plaintext = '0x012324B10AFBECDD' #0x012324B10AFBECDD
plaintext_numbers = []
for char in plaintext[2:]:
    num = int(char, 16)
    plaintext_numbers.append(num)

def encrypt(m, e, n):
    return pow(m, e, n)

def decrypt(c, d, n):
    return pow(c, d, n)

ciphertext_numbers = []
for m in plaintext_numbers:
    c = encrypt(m, e, n)
    ciphertext_numbers.append(c)

print("Ciphertext:", ciphertext_numbers)

decrypted_numbers = []
for c in ciphertext_numbers:
    m = decrypt(c, d, n)
    decrypted_numbers.append(m)

decrypted_hex = '0x' + ''.join([hex(num)[2:].upper() for num in decrypted_numbers])

# Print the decrypted plaintext
print("Decrypted plaintext:", decrypted_hex)