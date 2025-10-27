from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.Padding import pad
import binascii

key = bytes.fromhex('cf923be8da52631113752d5b32cef80b9d2bdadac85130811bee86868fe97204')
iv = bytes.fromhex('000102030405060708090a0b0c0d0e0f')
ciphertext = binascii.unhexlify(b"9fc8f90c93e824f602f189a7457fe97339f66a44bca4c05518af21657c5192660793dddc60fb248f71424834c910748fba68236fa281564930d1d7be80302e21650c50a1b3e6576d9e1e547766819c3a5b500b22ee753dd2d44ab3c8fd844d4b7b5699e6d1d7ca168f39dcdf2c35942947513f06d13a60d8c0ff07927591b0eeab97896c240e5343216ee1d0e3d8d1c107c44fdeacb94ddb35b8033cb0c7d235")

# Debug info
print(f"Key length: {len(key)} bytes")
print(f"IV length: {len(iv)} bytes")
print(f"Ciphertext length: {len(ciphertext)} bytes ({len(ciphertext) % 16} mod 16)")

# Try decrypting without unpadding first to see raw output
cipher = AES.new(key, AES.MODE_CBC, iv)
raw_decrypted = cipher.decrypt(ciphertext)

print(f"\nRaw decrypted (hex): {raw_decrypted.hex()}")
print(f"Last 16 bytes (hex): {raw_decrypted[-16:].hex()}")
print(f"Last byte value: {raw_decrypted[-1]}")

# Try manual padding check
last_byte = raw_decrypted[-1]
print(f"\nPadding byte indicates: {last_byte} bytes of padding")
if last_byte <= 16:
    padding = raw_decrypted[-last_byte:]
    print(f"Padding bytes (hex): {padding.hex()}")
    print(f"All padding bytes same? {all(b == last_byte for b in padding)}")

# Try unpadding manually if it looks valid
try:
    plaintext = unpad(raw_decrypted, AES.block_size)
    print(f"\n✓ Decrypted successfully: {plaintext.decode('utf-8', errors='replace')}")
except ValueError as e:
    print(f"\n✗ Padding error: {e}")
    # Show what the plaintext would be if we just strip the last byte
    print(f"\nAttempting without padding removal:")
    print(f"Raw output: {raw_decrypted.decode('utf-8', errors='replace')}")



# Encryption
cipher = AES.new(key, AES.MODE_CBC, iv)
encrypted_bytes = cipher.encrypt(pad(b'{"sta": "ok"}', 16))
print(encrypted_bytes.hex())