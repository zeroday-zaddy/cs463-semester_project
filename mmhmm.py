import des
class TextFormat:
    """For cool visual you know"""
    #red
    CIPHER='\x1b[5;91m' 
    #green
    PLAIN='\x1b[5;92m'
    #ending ascii escape
    ENDC='\x1b[0m'
def toblock64(text):
    """list of 8 ascii bytes"""

    ASCII_BITS = 8
    BLOCK_BITS = des.BLOCK_SIZE
    ASCII_BLOCKS = BLOCK_BITS // ASCII_BITS
    
    blocks = []
    b = 0b0
    i = 0
    for c in text:
        b += ord(c)
        b <<= ASCII_BITS
        i+=1

        if i % ASCII_BLOCKS == 0:
            b >>= ASCII_BITS
            blocks.append(b)
            b = 0b0
    if i % ASCII_BLOCKS != 0:
        b >>= ASCII_BITS
        blocks.append(b)
        b = 0b0

    return blocks

def blockToString(blocks):
    ASCII_MASK = 0xFF
    ASCII_BITS = 8
    BLOCK_BITS = des.BLOCK_SIZE
    ASCII_BLOCKS = BLOCK_BITS // ASCII_BITS
    
    message = ""
    for block in blocks:
        block_message = ""
        block2 = block
        for i in range(ASCII_BLOCKS):
            char = chr(block2 & ASCII_MASK)
            block2 >>= (ASCII_BITS)
            block_message = char + block_message
        message += block_message
        
    return message

def permute(block, bsize, ptable):
    """permute the 64 bits based 
    on the permutation table"""
    i = 1
    pb = 0b0
    for p in ptable:
        # get the bit in block
        shift = bsize - p
        bit = (block >> shift) & 1

        # place in new block
        shift = len(ptable)  - i
        pb += (bit << shift)

        i+=1
    return pb


def f_func(block, key):
    """block 32 bits and key is 48 bits"""
    expanded = permute(block, 
        bin_len(des.MASK32), des.E_BOX)
    
    substituted = sbox(expanded ^ key)

    permuted = permute(substituted,
        bin_len(des.MASK48), des.P)
    
    return permuted
    
        
def sbox(block):
    BLOCK_BITS = bin_len(des.MASK48)
    SUBBLOCK_BITS = bin_len(des.MASK6)
    SBOX_BLOCK_BITS = bin_len(des.MASK4)
    SBOX_VALUES = des.MASK4 + 1
    SUBBLOCKS = BLOCK_BITS // SUBBLOCK_BITS

    """print(f"BLOCK_BITS={BLOCK_BITS}\nSUBBLOCK_BITS={SUBBLOCK_BITS}\n" \
           f"SBOX_BLOCK_BITS={SBOX_BLOCK_BITS}\nSBOX_VALUES={SBOX_VALUES}\n" \
          f"SUBBLOCKS={SUBBLOCKS}\n")"""
    sbox_block = 0b0
    for i in range(SUBBLOCKS):
        subblock_shift = SUBBLOCKS-(i+1)
        shift = subblock_shift * SUBBLOCK_BITS
        
        subblock = block >> shift & des.MASK6
        # print(f"{subblock:06b}")

        row = (subblock >> 5) 
        row = (row << 1) + (subblock & 1)

        col = subblock >> 1 & des.MASK4

        subblock = get(des.S_BOXES[i+1], row, col, SBOX_VALUES)
        """print(f"{subblock:04b}")"""
        subblock <<= subblock_shift * SBOX_BLOCK_BITS

        """print('~', format(subblock, f"0{bin_len(des.MASK32)}b"),
         subblock_shift)"""

        sbox_block += subblock

        """print(format(sbox_block, f"0{(i+1)*SBOX_BLOCK_BITS}b"),
         subblock_shift)"""
    
    return sbox_block




def key_transform(key, round, encrypting):
    """key is 56 bits -> 48 bits"""
    KEY56_BITS = bin_len(des.MASK56)
    KEY48_BITS = bin_len(des.MASK48)
    HALF_MASK = des.MASK28
    HALF_BITS = bin_len(HALF_MASK)
    rotations = des.ROUND_TO_ROT[round]
    # left half
    c = key >> HALF_BITS
    # right half
    d = key & HALF_MASK
    
    if encrypting:
        c = lRot(c, rotations, HALF_BITS)
        d = lRot(d, rotations, HALF_BITS)
    elif round != 1:
        c = rRot(c, rotations, HALF_BITS)
        d = rRot(d, rotations, HALF_BITS)

    # 56 bit key for next round input
    c <<= HALF_BITS
    rotated_key = c + d

    # 48 bit key for f-function
    round_key = permute(rotated_key, KEY56_BITS, des.PC2)

    return (round_key, rotated_key)
    

def lRot(block, rotations, bsize):
    return (block << rotations) & (2**bsize-1) |\
        (block >> (bsize - rotations)) 
def rRot(block, rotations, bsize):
    return (block >> rotations) |\
        (block << (bsize - rotations)) & (2**bsize-1)


def fiestel(block, key):
    """block 64 bits, key 48 bits"""
    BLOCK_BITS = bin_len(des.MASK64)
    HALF_BITS = bin_len(des.MASK32)
    HALF_MASK = des.MASK32

    l = block >> HALF_BITS
    r = block & HALF_MASK

    l_fiestel = r
    l_fiestel <<= HALF_BITS
    r_fiestel = l ^ f_func(r, key)

    block_fiestel = l_fiestel + r_fiestel
    return block_fiestel

def rounds(block, key, encrypting):
    BLOCK_BITS = des.BLOCK_SIZE
    BLOCK_HALF_BITS = bin_len(des.MASK32)
    BLOCK_HALF_MASK = des.MASK32
    KEY64_BITS = bin_len(des.MASK64)
    KEY56_BITS = bin_len(des.MASK56)
    KEY48_BITS = bin_len(des.MASK48)


    initial_permutation_block = \
        permute(block, BLOCK_BITS, des.IP)
    fiestel_block = initial_permutation_block


    key56 = permute(key, KEY64_BITS, des.PC1)
    rotated_key = key56


    #print('--00',format(rotated_key, "056b"), format(key56, "014x"))

    for i in range(des.ROUNDS):
        round = i + 1
        (round_key, rotated_key) = \
            key_transform(rotated_key, round, encrypting)
        #print(f'--{round:02d}',format(rotated_key, "056b"), format(round_key, "012x"))
        
        fiestel_block = fiestel(fiestel_block, round_key)


    fiestel_block = fiestel_swap(fiestel_block)


    final_permute_block = \
        permute(fiestel_block, des.BLOCK_SIZE, des.IP_INV)
    return final_permute_block


def fiestel_swap(block):
    BLOCK_BITS = bin_len(des.MASK32)
    BLOCK_MASK = des.MASK32
    l = block >> BLOCK_BITS
    r = block & BLOCK_MASK
    l_fiestel = r
    l_fiestel <<= BLOCK_BITS
    r_fiestel = l

    fiestel_block = l_fiestel + r_fiestel
    return fiestel_block

def get(arr, row, col, cols):
    i = row * cols  + col
    return arr[i]

def bin_len(b):
    return len(bin(b)[2:])


def main():
    plaintext = input("Enter the message to encrpyt:\n")
    plaintext_blocks = toblock64(plaintext)
    key = int(input(f"\nEnter a key (hex) from 0 to {des.MASK64:#0x} (64 bits):\n"),16)


    print("\nEncrypting...")
    ciphertext_blocks = []
    for block in plaintext_blocks:
        ciphertext_block = rounds(block, key, encrypting=True)
        ciphertext_blocks.append(ciphertext_block)
    
    ciphertext = blockToString(ciphertext_blocks)
    print(f"This is the ciphertext:\n" \
        f"{TextFormat.CIPHER}{ciphertext}{TextFormat.ENDC}\n")

    print("Decrypting...")
    decrypted_blocks = []
    for block in ciphertext_blocks:
        decrypted_block = rounds(block, key, encrypting=False)
        decrypted_blocks.append(decrypted_block)
    
    decrypted = blockToString(decrypted_blocks)
    print(f"Your message decrypted:\n" \
        f"{TextFormat.PLAIN}{decrypted}{TextFormat.ENDC}")

if __name__ == "__main__":
    main()



    