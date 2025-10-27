#!/usr/bin/env python3
"""
Chain of Demands - Clean Decryption Script
Exploits the counter=0 vulnerability in LCG Oracle
"""

import json
from Crypto.Util.number import isPrime, long_to_bytes, inverse
import math

def extract_lcg_output(plaintext, ciphertext_hex, conversation_time):
    """
    Extract LCG output from known plaintext using XOR decryption.
    
    Encryption: ciphertext = plaintext_as_bytes32 XOR prime XOR time
    Therefore: prime = ciphertext XOR plaintext_as_bytes32 XOR time
    """
    # Convert plaintext to bytes32 (right-padded to 32 bytes)
    plaintext_bytes = plaintext.encode('utf-8').ljust(32, b'\x00')
    plaintext_int = int.from_bytes(plaintext_bytes, 'big')
    
    # Convert conversation time to bytes32 (little-endian as per contract)
    time_bytes = conversation_time.to_bytes(32, 'little')
    time_int = int.from_bytes(time_bytes, 'little')
    
    # Convert ciphertext
    ciphertext_int = int.from_bytes(bytes.fromhex(ciphertext_hex), 'big')
    
    # Extract: prime = ciphertext XOR plaintext XOR time
    prime = ciphertext_int ^ plaintext_int ^ time_int
    
    return prime

def recover_lcg_parameters(outputs):
    """
    Recover LCG parameters (m, c, n) from sequence of outputs.
    
    The LCG maintains state:
    - Call 0: state=seed, counter=0 -> returns seed (vulnerability!)
    - After call 0: state = seed
    - Call 1: state=seed, counter=1 -> returns (seed*m+c)%n
    - After call 1: state = (seed*m+c)%n
    - Call 2: state=(seed*m+c)%n, counter=2 -> returns (state*m+c)%n
    - etc.
    
    So the outputs form a sequence where:
    output[0] = seed
    output[1] = (output[0] * m + c) % n
    output[2] = (output[1] * m + c) % n
    ...
    """
    
    print("\n[*] Recovering LCG parameters from outputs...")
    print(f"    Number of outputs: {len(outputs)}\n")
    
    if len(outputs) < 3:
        print("[!] Need at least 3 outputs")
        return None
    
    # We have: x[i+1] = (x[i] * m + c) % n
    # Calculate differences
    x0, x1, x2, x3 = outputs[0], outputs[1], outputs[2], outputs[3]
    
    d1 = x1 - x0  # (x0*m + c) - x0 = x0*(m-1) + c
    d2 = x2 - x1  # (x1*m + c) - x1 = x1*(m-1) + c
    d3 = x3 - x2  # (x2*m + c) - x2 = x2*(m-1) + c
    
    print(f"    d1 (x1-x0) = {str(d1)[:50]}...")
    print(f"    d2 (x2-x1) = {str(d2)[:50]}...")
    print(f"    d3 (x3-x2) = {str(d3)[:50]}...\n")
    
    # Method: Use the fact that d[i+1]/d[i] ≈ m (mod n)
    # More precisely: d2 = m*d1 (mod n) when eliminating c
    # So: d2*d0 - d1^2 = 0 (mod n) in some formulations
    
    # Try: (d2 - d1) * x0 - d1 * x1 + d1 * x0 should help eliminate things
    # Better: use t[i] = x[i+1] - x[i], then t[i+1] = m*t[i] (mod n) [eliminating c]
    # This gives: t[i+1]*t[i-1] - t[i]^2 = 0 (mod n)
    
    # Calculate using 4 outputs to get multiple equations
    candidates = []
    
    # Method 1: t[2]*t[0] - t[1]^2 should be 0 mod n
    if len(outputs) >= 4:
        t0 = outputs[1] - outputs[0]
        t1 = outputs[2] - outputs[1]
        t2 = outputs[3] - outputs[2]
        
        val1 = abs(t1 * t1 - t0 * t2)
        if val1 > 0 and val1 > max(outputs):
            candidates.append(val1)
            print(f"    Candidate from t1^2 - t0*t2: {str(val1)[:50]}...")
    
    # Method 2: More equations if we have more outputs
    if len(outputs) >= 5:
        t3 = outputs[4] - outputs[3]
        val2 = abs(t2 * t2 - t1 * t3)
        if val2 > 0 and val2 > max(outputs):
            candidates.append(val2)
            print(f"    Candidate from t2^2 - t1*t3: {str(val2)[:50]}...")
    
    if len(outputs) >= 6:
        t4 = outputs[5] - outputs[4]
        val3 = abs(t3 * t3 - t2 * t4)
        if val3 > 0 and val3 > max(outputs):
            candidates.append(val3)
            print(f"    Candidate from t3^2 - t2*t4: {str(val3)[:50]}...")
    
    if not candidates:
        print("[!] No valid candidates found")
        return None
    
    # Find GCD of all candidates
    print("\n    Computing GCD of candidates...")
    n = candidates[0]
    for c in candidates[1:]:
        n = math.gcd(n, c)
    
    print(f"    Modulus n: {str(n)[:50]}...")
    print(f"    Bit length: {n.bit_length()}")
    
    # Verify n is a 256-bit prime
    if n.bit_length() != 256:
        print(f"[!] Modulus is not 256 bits")
        return None
    
    if not isPrime(n):
        print(f"[!] Modulus is not prime")
        return None
    
    print("    ✓ Modulus is a 256-bit prime!\n")
    
    # Now recover m and c
    # From: x1 = (x0 * m + c) % n and x2 = (x1 * m + c) % n
    # Subtract: x2 - x1 = m*(x1 - x0) % n
    # So: m = (x2 - x1) / (x1 - x0) mod n
    
    try:
        d1_mod = (x1 - x0) % n
        d2_mod = (x2 - x1) % n
        
        d1_inv = inverse(d1_mod, n)
        m = (d2_mod * d1_inv) % n
        
        print(f"    Multiplier m: {str(m)[:50]}...")
        print(f"    Bit length: {m.bit_length()}")
        
        # Recover c: x1 = (x0 * m + c) % n => c = (x1 - x0*m) % n
        c = (x1 - x0 * m) % n
        
        print(f"    Increment c: {str(c)[:50]}...")
        print(f"    Bit length: {c.bit_length()}\n")
        
        return x0, m, c, n  # x0 is the seed
        
    except Exception as e:
        print(f"[!] Error recovering m and c: {e}")
        return None

def verify_lcg_parameters(seed, m, c, n, outputs):
    """Verify that parameters reproduce the outputs correctly"""
    print("[*] Verifying LCG parameters...\n")
    
    state = seed
    all_match = True
    
    for i, expected_output in enumerate(outputs):
        # Simulate contract call with counter=i
        if i == 0:
            output = state  # counter=0 returns state unchanged
        else:
            output = (state * m + c) % n
        
        # Update state (contract updates self.state to output)
        state = output
        
        if output == expected_output:
            print(f"    ✓ Output {i} matches")
        else:
            print(f"    ✗ Output {i} MISMATCH")
            print(f"      Expected: {str(expected_output)[:50]}...")
            print(f"      Got:      {str(output)[:50]}...")
            all_match = False
    
    return all_match

def generate_rsa_primes(seed, m, c, n, num_primes=8):
    """Generate RSA primes using separate LCG instance"""
    print(f"\n[*] Generating {num_primes} RSA primes...\n")
    
    primes = []
    state = seed
    counter = 0
    max_iterations = 100000
    
    while len(primes) < num_primes and counter < max_iterations:
        # Simulate contract call
        if counter == 0:
            output = state
        else:
            output = (state * m + c) % n
        
        state = output
        counter += 1
        
        # Check if it's a 256-bit prime
        if output.bit_length() == 256 and isPrime(output):
            primes.append(output)
            print(f"    ✓ Found prime {len(primes)}/{num_primes} at iteration {counter}")
    
    if len(primes) < num_primes:
        print(f"[!] Only found {len(primes)}/{num_primes} primes")
        return None
    
    return primes

def decrypt_rsa_messages(rsa_messages, primes):
    """Decrypt RSA messages using multi-prime RSA"""
    print("\n[*] Computing RSA private key...\n")
    
    # Calculate N (product of all primes)
    N = 1
    for p in primes:
        N *= p
    
    print(f"    RSA modulus N: {N.bit_length()} bits")
    
    # Calculate phi (Euler's totient)
    phi = 1
    for p in primes:
        phi *= (p - 1)
    
    e = 65537
    
    # Calculate private exponent
    try:
        d = inverse(e, phi)
        print("    ✓ Private exponent computed\n")
    except:
        print("[!] Failed to compute private exponent")
        return []
    
    # Decrypt each message
    print("[*] Decrypting RSA messages...\n")
    decrypted = []
    
    for msg in rsa_messages:
        ct_bytes = bytes.fromhex(msg['ciphertext'])
        ct_int = int.from_bytes(ct_bytes, 'little')
        
        # Decrypt
        pt_int = pow(ct_int, d, N)
        pt_bytes = long_to_bytes(pt_int)
        
        try:
            plaintext = pt_bytes.decode('utf-8', errors='ignore').rstrip('\x00')
            print(f"    [+] Decrypted: \"{plaintext}\"")
            decrypted.append(plaintext)
        except:
            print(f"    [+] Decrypted (hex): {pt_bytes.hex()}")
            decrypted.append(pt_bytes.hex())
    
    return decrypted

def main():
    print("=" * 70)
    print("Chain of Demands - Clean Decryption")
    print("=" * 70)
    
    # Load chat log
    with open('chat_log.json', 'r') as f:
        chat_log = json.load(f)
    
    print(f"\n[+] Loaded {len(chat_log)} messages")
    
    # Extract LCG outputs from known plaintexts
    print("\n[PHASE 1] Extracting LCG outputs from known plaintexts")
    print("=" * 70)
    
    outputs = []
    for i, msg in enumerate(chat_log):
        if msg['mode'] == 'LCG-XOR' and msg['plaintext'] != '[ENCRYPTED]':
            output = extract_lcg_output(
                msg['plaintext'],
                msg['ciphertext'],
                msg['conversation_time']
            )
            outputs.append(output)
            print(f"\n  Message {i}:")
            print(f"    Plaintext: \"{msg['plaintext']}\"")
            print(f"    LCG output: {str(output)[:60]}...")
    
    print(f"\n[+] Extracted {len(outputs)} LCG outputs")
    print(f"[+] Output 0 (seed): {hex(outputs[0])}")
    
    # Recover LCG parameters
    print("\n" + "=" * 70)
    print("[PHASE 2] Recovering LCG parameters")
    print("=" * 70)
    
    result = recover_lcg_parameters(outputs)
    if not result:
        print("[!] Failed to recover parameters")
        return
    
    seed, m, c, n = result
    
    print("\n[+] LCG Parameters recovered:")
    print(f"    Seed: {hex(seed)}")
    print(f"    m:    {hex(m)}")
    print(f"    c:    {hex(c)}")
    print(f"    n:    {hex(n)}")
    
    # Verify parameters
    print("\n" + "=" * 70)
    print("[PHASE 3] Verification")
    print("=" * 70 + "\n")
    
    if not verify_lcg_parameters(seed, m, c, n, outputs):
        print("\n[!] Verification failed!")
        return
    
    print("\n[+] All outputs verified successfully!")
    
    # Generate RSA primes and decrypt
    print("\n" + "=" * 70)
    print("[PHASE 4] RSA Decryption")
    print("=" * 70)
    
    primes = generate_rsa_primes(seed, m, c, n)
    if not primes:
        print("[!] Failed to generate RSA primes")
        return
    
    # Get RSA messages
    rsa_messages = [msg for msg in chat_log if msg['mode'] == 'RSA']
    
    if not rsa_messages:
        print("\n[!] No RSA messages found")
        return
    
    decrypted = decrypt_rsa_messages(rsa_messages, primes)
    
    # Summary
    print("\n" + "=" * 70)
    print("DECRYPTION COMPLETE")
    print("=" * 70)
    print(f"\n[+] Successfully decrypted {len(decrypted)} RSA messages")
    
    for i, msg in enumerate(decrypted):
        print(f"\n  RSA Message {i+1}: {msg}")
    
    # Look for flag
    print("\n" + "=" * 70)
    for msg in decrypted:
        if 'flag' in msg.lower() or '@flare-on.com' in msg.lower():
            print(f"\n🎯 FLAG FOUND: {msg}")
            print("=" * 70)

if __name__ == '__main__':
    main()