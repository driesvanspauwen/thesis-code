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