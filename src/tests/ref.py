def ref_sha1_round(inputs, w, round_num=0):
    """Reference implementation matching the C code"""
    a, b, c, d, e = inputs
    
    # Constants for each round
    constants = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6]
    
    # Functions for each round type
    if round_num == 0:
        f = (b & c) | ((~b) & d)
    elif round_num == 1:
        f = b ^ c ^ d
    elif round_num == 2:
        f = (b & c) | (b & d) | (c & d)
    else:  # round_num == 3
        f = b ^ c ^ d
    
    # ROL function (rotate left)
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    temp = (rol(a, 5) + f + e + w + constants[round_num]) & 0xFFFFFFFF
    
    return [
        temp,
        a,
        rol(b, 30),
        c,
        d
    ]

def ref_aes_round(input_block, key_block):
    """Reference implementation of AES round for testing"""
    # AES S-box lookup table
    sbox = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    def gf_time(x):
        """Galois Field multiplication by 2"""
        return ((x << 1) ^ (((x >> 7) & 1) * 0x1b)) & 0xff
    
    # SubBytes + ShiftRows
    shifted = [
        sbox[input_block[0]], sbox[input_block[5]], sbox[input_block[10]], sbox[input_block[15]],
        sbox[input_block[4]], sbox[input_block[9]], sbox[input_block[14]], sbox[input_block[3]],
        sbox[input_block[8]], sbox[input_block[13]], sbox[input_block[2]], sbox[input_block[7]],
        sbox[input_block[12]], sbox[input_block[1]], sbox[input_block[6]], sbox[input_block[11]]
    ]
    
    # MixColumns + AddRoundKey
    output = [0] * 16
    for i in range(4):
        t = shifted[i * 4 + 0] ^ shifted[i * 4 + 1] ^ shifted[i * 4 + 2] ^ shifted[i * 4 + 3]
        output[i * 4 + 0] = (t ^ gf_time(shifted[i * 4 + 0] ^ shifted[i * 4 + 1]) ^ shifted[i * 4 + 0] ^ key_block[i * 4 + 0]) & 0xff
        output[i * 4 + 1] = (t ^ gf_time(shifted[i * 4 + 1] ^ shifted[i * 4 + 2]) ^ shifted[i * 4 + 1] ^ key_block[i * 4 + 1]) & 0xff
        output[i * 4 + 2] = (t ^ gf_time(shifted[i * 4 + 2] ^ shifted[i * 4 + 3]) ^ shifted[i * 4 + 2] ^ key_block[i * 4 + 2]) & 0xff
        output[i * 4 + 3] = (t ^ gf_time(shifted[i * 4 + 3] ^ shifted[i * 4 + 0]) ^ shifted[i * 4 + 3] ^ key_block[i * 4 + 3]) & 0xff
    
    return output

def ref_simon32(input_block, key_block, rounds=32):
    """Reference implementation of Simon32 encryption for testing"""
    
    def ror(x, r, bits=16):
        """Rotate right for 16-bit values"""
        return ((x >> r) | (x << (bits - r))) & ((1 << bits) - 1)
    
    def rol(x, r, bits=16):
        """Rotate left for 16-bit values"""
        return ((x << r) | (x >> (bits - r))) & ((1 << bits) - 1)
    
    def simon_round(x, y, k):
        """Single Simon round"""
        tmp = (rol(x, 1) & rol(x, 8)) ^ y ^ rol(x, 2)
        y = x
        x = tmp ^ k
        return x & 0xFFFF, y & 0xFFFF
    
    # Convert byte arrays to 16-bit words (little-endian)
    x = input_block[1] | (input_block[0] << 8)
    y = input_block[3] | (input_block[2] << 8)
    
    # Key schedule - convert 8 bytes to 4 x 16-bit keys
    keys = [0] * rounds
    for i in range(4):
        keys[3 - i] = key_block[i * 2 + 1] | (key_block[i * 2] << 8)
    
    # Key expansion
    z0 = 0b10110011100001101010010001011111
    for i in range(4, rounds):
        tmp = ror(keys[i - 1], 3)
        tmp ^= keys[i - 3]
        tmp ^= ror(tmp, 1)
        keys[i] = (~keys[i - 4] ^ tmp ^ 3 ^ ((z0 >> (i - 4)) & 1)) & 0xFFFF
    
    # Encryption rounds
    for i in range(rounds):
        x, y = simon_round(x, y, keys[i])
    
    # Convert back to bytes (little-endian)
    output = [0] * 4
    output[0] = (x >> 8) & 0xFF
    output[1] = x & 0xFF
    output[2] = (y >> 8) & 0xFF
    output[3] = y & 0xFF
    
    return output

def ref_sha1_2blocks(block1, block2):
    """Reference implementation for 2-block SHA-1 processing"""
    # Initialize SHA-1 state (standard initial values)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    
    # Process block1
    print(f"Ref Processing block1: {[hex(x) for x in block1]}")
    ref_sha1_block(block1, state)
    
    # Process block2  
    print(f"Ref Processing block2: {[hex(x) for x in block2]}")
    ref_sha1_block(block2, state)
    
    return state

def ref_sha1_block(block, state):
    """Reference implementation of sha1_block function from the C code"""
    # ROL function (rotate left)
    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF
    
    # Expand the 16-word block into 80 words (w array)
    w = list(block)  # First 16 words are the input block
    
    # Expand to 80 words using the SHA-1 message schedule
    for i in range(16, 80):
        w.append(rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1) & 0xFFFFFFFF)
    
    # Save original state for final addition
    ori_state = list(state)
    
    # Create a working copy of the state
    working_state = list(state)
    
    # Process 80 rounds
    for i in range(80):
        print(f"Ref Round {i}: {[hex(x) for x in working_state]}")
        if i <= 19:
            # Round 1 (rounds 0-19): use round type 0
            new_state = ref_sha1_round(working_state, w[i], round_num=0)
        elif i <= 39:
            # Round 2 (rounds 20-39): use round type 1
            new_state = ref_sha1_round(working_state, w[i], round_num=1)
        elif i <= 59:
            # Round 3 (rounds 40-59): use round type 2
            new_state = ref_sha1_round(working_state, w[i], round_num=2)
        else:
            # Round 4 (rounds 60-79): use round type 3
            new_state = ref_sha1_round(working_state, w[i], round_num=3)
        
        # Update working state for next round
        working_state[:] = new_state
    
    # Add original state to final state (SHA-1 requirement)
    for i in range(5):
        state[i] = (working_state[i] + ori_state[i]) & 0xFFFFFFFF