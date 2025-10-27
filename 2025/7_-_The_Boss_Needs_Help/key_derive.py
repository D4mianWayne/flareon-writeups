import struct
import ctypes

def sha256_hash(data):
    """
    Python implementation of the SHA-256 hash function
    Equivalent to the provided C++ code
    """
    # SHA-256 initial hash values (first 32 bits of fractional parts of square roots of first 8 primes)
    h = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    # SHA-256 constants (first 32 bits of fractional parts of cube roots of first 64 primes)
    k = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    # Pre-processing
    original_byte_len = len(data)
    original_bit_len = original_byte_len * 8
    
    # Append the bit '1' to the message
    data += b'\x80'
    
    # Append 0 ≤ k < 512 bits '0', so that the resulting message length (in bits)
    # is congruent to 448 (mod 512)
    while (len(data) * 8) % 512 != 448:
        data += b'\x00'
    
    # Append length of message (before pre-processing), in bits, as 64-bit big-endian integer
    data += struct.pack('>Q', original_bit_len)
    
    # Process the message in successive 512-bit chunks
    for chunk_start in range(0, len(data), 64):
        chunk = data[chunk_start:chunk_start + 64]
        
        # Break chunk into sixteen 32-bit big-endian words w[0..15]
        w = [0] * 64
        for i in range(16):
            w[i] = struct.unpack('>I', chunk[i*4:i*4+4])[0]
        
        # Extend the sixteen 32-bit words into sixty-four 32-bit words
        for i in range(16, 64):
            s0 = _right_rotate(w[i-15], 7) ^ _right_rotate(w[i-15], 18) ^ (w[i-15] >> 3)
            s1 = _right_rotate(w[i-2], 17) ^ _right_rotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) & 0xFFFFFFFF
        
        # Initialize working variables to current hash value
        a, b, c, d, e, f, g, h_temp = h
        
        # Main loop
        for i in range(64):
            s1 = _right_rotate(e, 6) ^ _right_rotate(e, 11) ^ _right_rotate(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h_temp + s1 + ch + k[i] + w[i]) & 0xFFFFFFFF
            s0 = _right_rotate(a, 2) ^ _right_rotate(a, 13) ^ _right_rotate(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (s0 + maj) & 0xFFFFFFFF
            
            h_temp = g
            g = f
            f = e
            e = (d + temp1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xFFFFFFFF
        
        # Add the compressed chunk to the current hash value
        h[0] = (h[0] + a) & 0xFFFFFFFF
        h[1] = (h[1] + b) & 0xFFFFFFFF
        h[2] = (h[2] + c) & 0xFFFFFFFF
        h[3] = (h[3] + d) & 0xFFFFFFFF
        h[4] = (h[4] + e) & 0xFFFFFFFF
        h[5] = (h[5] + f) & 0xFFFFFFFF
        h[6] = (h[6] + g) & 0xFFFFFFFF
        h[7] = (h[7] + h_temp) & 0xFFFFFFFF
    
    # Produce the final hash value (big-endian)
    return b''.join(struct.pack('>I', x) for x in h)

def _right_rotate(n, b):
    """Right rotate a 32-bit integer n by b bits"""
    return ((n >> b) | (n << (32 - b))) & 0xFFFFFFFF

# Simplified version that matches the original function signature more closely
def hash_data(input_data, output_buffer=None):
    """
    Simplified version that matches the original C function behavior
    
    Args:
        input_data: bytes or bytearray to hash
        output_buffer: optional bytearray to write the result to
    
    Returns:
        bytes: SHA-256 hash result
    """
    result = sha256_hash(input_data)
    
    if output_buffer is not None:
        # Copy result to output buffer like the original function
        output_len = min(len(output_buffer), len(result))
        output_buffer[:output_len] = result[:output_len]
    
    return result

# Alternative implementation using Python's built-in hashlib for verification
import hashlib

def sha256_verify(data):
    """Verify our implementation against Python's built-in SHA-256"""
    h = hashlib.sha256()
    h.update(data)
    return h.digest()
    # Convert back to hex

def xor_hashes(hex1, hex2):
    """
    XOR two hexadecimal SHA-256 hash strings
    
    Args:
        hex1: First hash as hex string
        hex2: Second hash as hex string
    
    Returns:
        str: XOR result as hex string
    """
    # Convert hex strings to bytes
    # XOR the bytes
    result_bytes = bytes(a ^ b for a, b in zip(hex1, hex2))
    
    # Convert back to hex
    return result_bytes.hex()

# Example usage
if __name__ == "__main__":
    key1 = b"TheBoss@THUNDERNODE"
    key2 = b"miami06" # peanut06 -> TheBoss@THUNDERNODE06
    
    # Our implementation
    hash1 = sha256_hash(key1)
    print(f"Our SHA-256: {hash1.hex()}")
    hash2 = sha256_hash(key2)
    print(f"Our SHA-256: {hash2.hex()}")


    result = xor_hashes(hash1, hash2)
    print(f"XOR result: {result}")

    
    # # Built-in implementation for verification
    # builtin_hash = hashlib.sha256(test_data).digest()
    # print(f"Built-in:   {builtin_hash.hex()}")
    
    # Verify they match
