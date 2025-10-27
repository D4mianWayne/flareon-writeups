#!/usr/bin/env python3
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
from email.utils import formatdate
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
from datetime import datetime

RESPONSE_JSON = {
    "d": "5134c8a46686f2950972712f2cd84174"
}

IV = bytes.fromhex('000102030405060708090a0b0c0d0e0f')

def get_utc_hour():
    """Get current UTC hour as zero-padded string (00-23)"""
    return f"{datetime.utcnow().hour:02d}"

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
    return result_bytes

def calculate_key():
    """Calculate AES key from SHA256("peanut" + UTC_hour) + SHA256("TheBoss@THUNDERNODE")"""
    utc_hour = get_utc_hour()
    
    # First part: SHA256("peanut" + hour)
    part1 = hashlib.sha256(f"peanut{utc_hour}".encode()).digest()
    
    # Second part: SHA256("TheBoss@ThunderNode")
    part2 = hashlib.sha256("TheBoss@THUNDERNODE".encode()).digest()
    print(f"Key1: {part1.hex()}")
    print(f"Key2: {part2.hex()}")
    
    # Combine both (64 bytes total, use first 32 for AES-256)
    key = xor_hashes(part1, part2)
    
    print(f"[+] Key calculation: UTC hour = {utc_hour}")
    print(f"[+] Key (hex): {key.hex()}")
    
    return key

def decrypt_aes_cbc(ciphertext, key, iv):
    """Decrypt data using AES-CBC with detailed padding analysis"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    raw_decrypted = cipher.decrypt(ciphertext)

    print(f"\n[DEBUG] Raw decrypted (hex): {raw_decrypted.hex()}")
    print(f"[DEBUG] Last 16 bytes (hex): {raw_decrypted[-16:].hex()}")
    print(f"[DEBUG] Last byte value: {raw_decrypted[-1]}")

    # Manual padding check
    last_byte = raw_decrypted[-1]
    print(f"\n[DEBUG] Padding byte indicates: {last_byte} bytes of padding")
    if last_byte <= 16:
        padding = raw_decrypted[-last_byte:]
        print(f"[DEBUG] Padding bytes (hex): {padding.hex()}")
        print(f"[DEBUG] All padding bytes same? {all(b == last_byte for b in padding)}")

    # Try unpadding
    try:
        plaintext = unpad(raw_decrypted, AES.block_size)
        print(f"\n[DEBUG] ✓ Decrypted successfully: {plaintext.decode('utf-8', errors='replace')}")
        return plaintext
    except ValueError as e:
        print(f"\n[DEBUG] ✗ Padding error: {e}")
        print(f"[DEBUG] Attempting without padding removal:")
        print(f"[DEBUG] Raw output: {raw_decrypted.decode('utf-8', errors='replace')}")
        # Return raw decrypted data without unpadding
        return raw_decrypted


def encrypt_aes_cbc(plaintext, key, iv):
    """Encrypt data using AES-CBC"""
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    return ciphertext

class CustomHandler(BaseHTTPRequestHandler):
    server_version = "SimpleHTTP/0.6 Python/3.10.11"
    sys_version = ""
    protocol_version = "HTTP/1.0"
    
    def dump_request(self):
        """Dump the raw request details"""
        print("\n" + "="*60)
        print("RAW REQUEST RECEIVED")
        print("="*60)
        
        # Request line
        print(f"Request Line: {self.command} {self.path} {self.request_version}")
        
        # Headers
        print("\nHeaders:")
        for header, value in self.headers.items():
            print(f"  {header}: {value}")
        
        # Body (if present)
        content_length = self.headers.get('Content-Length')
        body = b''
        encrypted_data = None
        
        if content_length:
            try:
                length = int(content_length)
                if length > 0:
                    body = self.rfile.read(length)
                    print(f"\nBody ({length} bytes):")
                    print("  Hex:", ' '.join(f'{b:02x}' for b in body))
                    try:
                        body_str = body.decode('utf-8')
                        print("  UTF-8:", body_str)
                        
                        # Try to parse as JSON and extract 'd' field
                        try:
                            json_data = json.loads(body_str)
                            if 'd' in json_data:
                                print(f"\n[+] Found 'd' field in JSON: {json_data['d']}")
                                # Convert hex string to bytes for decryption
                                encrypted_data = bytes.fromhex(json_data['d'])
                                print(f"[+] Encrypted data ({len(encrypted_data)} bytes): {encrypted_data.hex()}")
                        except json.JSONDecodeError:
                            print("  [!] Not valid JSON")
                    except UnicodeDecodeError:
                        print("  UTF-8: <binary data>")
            except ValueError:
                print("\nBody: Invalid Content-Length")
        else:
            print("\nBody: <none>")
        
        print("="*60 + "\n")
        return body, encrypted_data
    
    def send_json_response(self):
        """Send JSON response"""
        body = json.dumps(RESPONSE_JSON, separators=(',', ':')).encode("utf-8")
        self.send_response(200, "OK")
        self.send_header("Server", self.server_version)
        self.send_header("Date", formatdate(timeval=None, localtime=False, usegmt=True))
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    
    def send_encrypted_response(self, data_dict):
        """Encrypt and send JSON response wrapped in {"d": <encrypted_hex>}"""
        # Convert dict to JSON
        json_data = json.dumps(data_dict, separators=(',', ':')).encode("utf-8")
        print(f"[+] Plaintext JSON: {json_data.decode()}")
        
        # Calculate key and encrypt
        key = calculate_key()
        encrypted = encrypt_aes_cbc(json_data, key, IV)
        
        print(f"[+] Encrypted ({len(encrypted)} bytes): {encrypted.hex()}")
        
        # Wrap encrypted data in JSON with 'd' field as hex string
        response_json = {"d": encrypted.hex()}
        response_body = json.dumps(response_json, separators=(',', ':')).encode("utf-8")
        
        print(f"[+] Response JSON: {response_body.decode()}")
        
        # Send response
        self.send_response(200, "OK")
        self.send_header("Server", self.server_version)
        self.send_header("Date", formatdate(timeval=None, localtime=False, usegmt=True))
        self.send_header("Content-type", "application/json")
        self.send_header("Content-Length", str(len(response_body)))
        self.end_headers()
        self.wfile.write(response_body)
    
    def do_GET(self):
        body, encrypted_data = self.dump_request()
        if self.path == "/good":
            self.send_json_response()
        elif self.path == "/get":
            # Send encrypted command response for /get endpoint
            response_data = {
                "msg": "cmd",
                "d": {
                    "cid": 6,
                    "dt": 20,
                    "np": "TheBoss@THUNDERNODE"
                }
            }
            self.send_encrypted_response(response_data)
        else:
            self.send_error(404, "Not Found")
    
    def do_POST(self):
        body, encrypted_data = self.dump_request()
        
        if self.path == "/":
            # Decrypt received data from 'd' field
            if encrypted_data:
                try:
                    key = calculate_key()
                    decrypted = decrypt_aes_cbc(encrypted_data, key, IV)
                    print(f"[+] Decrypted data: {decrypted.decode('utf-8', errors='replace')}")
                    
                    # Parse JSON
                    try:
                        data = json.loads(decrypted.decode('utf-8', errors='replace'))
                        print(f"[+] Parsed JSON: {data}")
                    except json.JSONDecodeError as e:
                        print(f"[-] JSON parse error: {e}")
                except Exception as e:
                    print(f"[-] Decryption error: {e}")
                    self.send_error(400, "Bad Request")
                    return
            
            # Send encrypted response
            response_data = {"sta": "ok"}
            self.send_encrypted_response(response_data)
            
        elif self.path == "/re":
            # Send encrypted command response
            response_data = {
                "msg": "cmd",
                "d": {
                    "cid": 6,
                    "dt": 20,
                    "np": "TheBoss@THUNDERNODE"
                }
            }
            self.send_encrypted_response(response_data)
        else:
            self.send_error(404, "Not Found")

def run(port=8080):
    server_address = ('', port)
    httpd = HTTPServer(server_address, CustomHandler)
    print(f"[*] Serving on http://localhost:{port}/")
    print(f"[*] Endpoints: /good (GET), / (POST), /re (POST)")
    print(f"[*] IV: {IV.hex()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down server.")
        httpd.server_close()

if __name__ == "__main__":
    run()