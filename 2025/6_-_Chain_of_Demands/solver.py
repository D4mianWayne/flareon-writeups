#!/usr/bin/env python3
"""
Chain of Demands - Complete Recovery (Handles Round Gaps)
"""

import json
import hashlib
from Crypto.Util.number import isPrime, inverse, GCD
import itertools

def extract_outputs(chat_log):
    """Extract LCG outputs from XOR'd ciphertexts"""
    outputs = []
    rounds = []
    for entry in chat_log:
        if entry['mode'] != 'LCG-XOR':
            continue
        
        cipher_bytes = bytes.fromhex(entry['ciphertext'])
        plain_bytes = entry['plaintext'].encode('utf-8').ljust(32, b'\x00')
        time_bytes = entry['conversation_time'].to_bytes(32, 'little')
        
        output_bytes = bytes(c ^ p ^ t for c, p, t in zip(cipher_bytes, plain_bytes, time_bytes))
        output = int.from_bytes(output_bytes, 'little')
        outputs.append(output)
        rounds.append(entry['conversation_time'])
    
    return outputs, rounds

def solve_lcg_with_gaps(outputs, rounds):
    """
    Solve LCG parameters with non-consecutive rounds
    """
    print("\n[*] Solving LCG parameters with round gaps...")
    
    # Critical insight: Round 0 output is the multiplier m!
    m = outputs[0]
    print(f"[+] Multiplier m from round 0: {hex(m)[:50]}...")
    
    # We need to account for the gaps in rounds
    # The state evolves as: state_{k} = (m * state_{k-1} + c) % n
    # But with gaps, we have: state_{r} = m^gap * state_{r-gap} + c * (m^gap - 1) * inv(m-1) mod n
    
    # Let's use the mathematical relationships for gaps
    equations = []
    for i in range(1, len(outputs)):
        gap = rounds[i] - rounds[i-1]
        prev_output = outputs[i-1]
        curr_output = outputs[i]
        equations.append((gap, prev_output, curr_output))
    
    print(f"[*] Analyzing {len(equations)} transitions with gaps: {[eq[0] for eq in equations]}")
    
    # For each gap, we have:
    # output_curr = m^gap * output_prev + c * (m^gap - 1) * inv(m-1) mod n
    
    # Let's find n by creating equations that should be multiples of n
    candidates = set()
    
    for i in range(len(equations)):
        for j in range(i+1, len(equations)):
            gap1, prev1, curr1 = equations[i]
            gap2, prev2, curr2 = equations[j]
            
            # Calculate m^gap for both (using large temp modulus)
            m_gap1 = pow(m, gap1, 2**512)
            m_gap2 = pow(m, gap2, 2**512)
            
            # Calculate the geometric series sums
            S1 = (m_gap1 - 1) // (m - 1) if (m_gap1 - 1) % (m - 1) == 0 else None
            S2 = (m_gap2 - 1) // (m - 1) if (m_gap2 - 1) % (m - 1) == 0 else None
            
            if S1 is None or S2 is None:
                continue
            
            # We have:
            # curr1 = m_gap1 * prev1 + c * S1 mod n
            # curr2 = m_gap2 * prev2 + c * S2 mod n
            
            # Eliminate c:
            # (curr1 - m_gap1 * prev1) * S2 = (curr2 - m_gap2 * prev2) * S1 mod n
            left = (curr1 - m_gap1 * prev1) * S2
            right = (curr2 - m_gap2 * prev2) * S1
            diff = abs(left - right)
            
            if diff > max(outputs):
                candidates.add(diff)
    
    # Also try direct approach with GCD of multiple differences
    for i in range(len(equations) - 1):
        gap1, prev1, curr1 = equations[i]
        gap2, prev2, curr2 = equations[i+1]
        
        m_gap1 = pow(m, gap1, 2**512)
        m_gap2 = pow(m, gap2, 2**512)
        
        S1 = (m_gap1 - 1) // (m - 1) if (m_gap1 - 1) % (m - 1) == 0 else None
        S2 = (m_gap2 - 1) // (m - 1) if (m_gap2 - 1) % (m - 1) == 0 else None
        
        if S1 is None or S2 is None:
            continue
        
        val1 = curr1 - m_gap1 * prev1
        val2 = curr2 - m_gap2 * prev2
        
        n_candidate = GCD(val1, val2)
        if n_candidate > max(outputs):
            candidates.add(n_candidate)
    
    print(f"[*] Found {len(candidates)} modulus candidates")
    
    # Test each candidate
    for n_candidate in sorted(candidates):
        if n_candidate <= max(outputs) or n_candidate.bit_length() > 256:
            continue
            
        print(f"[*] Testing modulus: {hex(n_candidate)[:50]}...")
        
        # Solve for c using first equation
        gap1, prev1, curr1 = equations[0]
        m_gap1 = pow(m, gap1, n_candidate)
        
        try:
            S1 = (m_gap1 - 1) * inverse(m - 1, n_candidate) % n_candidate
            c_candidate = (curr1 - m_gap1 * prev1) * inverse(S1, n_candidate) % n_candidate
        except:
            continue
        
        # Verify with all outputs
        valid = True
        for i in range(len(outputs)):
            if i == 0:
                # Round 0 should be m
                if outputs[0] != m:
                    valid = False
                    break
            else:
                gap = rounds[i] - rounds[i-1]
                prev_output = outputs[i-1]
                
                m_gap = pow(m, gap, n_candidate)
                S = (m_gap - 1) * inverse(m - 1, n_candidate) % n_candidate
                expected = (m_gap * prev_output + c_candidate * S) % n_candidate
                
                if expected != outputs[i]:
                    valid = False
                    break
        
        if valid:
            print("[+] Valid parameters found!")
            
            # Find initial seed
            # We know: output_1 = m^rounds[1] * seed + c * S mod n
            # Where S = (m^rounds[1] - 1) * inv(m-1) mod n
            
            first_gap = rounds[1]  # From round 0 to round 4
            m_gap = pow(m, first_gap, n_candidate)
            S = (m_gap - 1) * inverse(m - 1, n_candidate) % n_candidate
            
            try:
                seed = (outputs[1] - c_candidate * S) * inverse(m_gap, n_candidate) % n_candidate
                print(f"[+] Initial seed: {hex(seed)[:50]}...")
                return seed, m, c_candidate, n_candidate
            except:
                continue
    
    return None

def brute_force_modulus(outputs, rounds, m):
    """Brute force common 256-bit moduli"""
    print("\n[*] Trying common 256-bit primes...")
    
    common_primes = [
        2**256 - 189,
        2**256 - 357,
        2**256 - 617,
        2**256 - 4803,
        2**255 - 19,
        2**255 - 31,
        2**256 - 2**224 + 2**192 + 2**96 - 1,  # P-256
    ]
    
    for n in common_primes:
        if not isPrime(n):
            continue
            
        print(f"[*] Testing: {hex(n)[:50]}...")
        
        # Try to find c that works
        # Use first transition: round 0 -> round 4
        gap = rounds[1] - rounds[0]  # 4
        prev_output = outputs[0]  # m
        curr_output = outputs[1]
        
        m_gap = pow(m, gap, n)
        try:
            S = (m_gap - 1) * inverse(m - 1, n) % n
            c = (curr_output - m_gap * prev_output) * inverse(S, n) % n
        except:
            continue
        
        # Verify all outputs
        valid = True
        for i in range(len(outputs)):
            if i == 0:
                if outputs[0] != m:
                    valid = False
                    break
            else:
                gap = rounds[i] - rounds[i-1]
                prev_output = outputs[i-1]
                
                m_gap = pow(m, gap, n)
                S = (m_gap - 1) * inverse(m - 1, n) % n
                expected = (m_gap * prev_output + c * S) % n
                
                if expected != outputs[i]:
                    valid = False
                    break
        
        if valid:
            print("[+] Found valid parameters with common prime!")
            
            # Find seed
            first_gap = rounds[1]
            m_gap = pow(m, first_gap, n)
            S = (m_gap - 1) * inverse(m - 1, n) % n
            seed = (outputs[1] - c * S) * inverse(m_gap, n) % n
            
            return seed, m, c, n
    
    return None

def verify_lcg_operation(seed, m, c, n, outputs, rounds):
    """Verify LCG operation matches all outputs"""
    print("\n[*] Verifying LCG operation...")
    
    # Track the actual state progression
    state = seed
    verification_passed = True
    
    print("    Round progression:")
    for i, round_num in enumerate(rounds):
        if i == 0:
            # For round 0, contract returns m
            calculated = m
            print(f"      Round 0: returns m = {hex(m)[:20]}...")
        else:
            # Calculate how many steps from previous round
            prev_round = rounds[i-1]
            steps = round_num - prev_round
            
            # Advance state through each intermediate round
            current_state = state
            for step in range(1, steps + 1):
                current_round = prev_round + step
                if current_round == 0:
                    next_output = m
                else:
                    next_output = (m * current_state + c) % n
                current_state = next_output
            
            calculated = current_state
            print(f"      Round {round_num}: {steps} steps from round {prev_round}")
        
        match = "✓" if calculated == outputs[i] else "✗"
        print(f"        {match} Expected: {hex(outputs[i])[:40]}...")
        print(f"          Got: {hex(calculated)[:40]}...")
        
        if calculated != outputs[i]:
            verification_passed = False
        
        # Update state for next verification
        state = outputs[i]  # Contract updates state with output
    
    return verification_passed

def generate_rsa_primes(seed, m, c, n, num_primes=8):
    """Generate RSA primes using the LCG"""
    print(f"\n[*] Generating {num_primes} RSA primes from LCG...")
    
    primes = []
    state = seed
    round_counter = 0
    max_iterations = 100000
    
    while len(primes) < num_primes and round_counter < max_iterations:
        # Simulate contract call
        if round_counter == 0:
            output = m
        else:
            output = (m * state + c) % n
        
        # Contract updates state
        state = output
        
        # Check if prime
        if output.bit_length() == 256 and isPrime(output):
            primes.append(output)
            print(f"    [+] Prime {len(primes)}/{num_primes} at round {round_counter}")
        
        round_counter += 1
    
    if len(primes) < num_primes:
        print(f"[-] Only found {len(primes)}/{num_primes} primes")
        return None
    
    return primes

def compute_rsa_key(primes):
    """Compute RSA private key"""
    print("\n[*] Computing RSA key...")
    
    N = 1
    for p in primes:
        N *= p
    
    print(f"    Modulus: {N.bit_length()} bits")
    
    phi = 1
    for p in primes:
        phi *= (p - 1)
    
    e = 65537
    
    try:
        d = inverse(e, phi)
        print("    Private exponent computed")
        return (N, e, d, primes)
    except:
        print("[-] Failed to compute private exponent")
        return None

def decrypt_rsa_messages(chat_log, rsa_key):
    """Decrypt RSA messages"""
    print("\n[*] Decrypting RSA messages...")
    
    N, e, d, primes = rsa_key
    
    rsa_messages = [msg for msg in chat_log if msg['mode'] == 'RSA']
    
    if not rsa_messages:
        print("    No RSA messages found")
        return []
    
    decrypted = []
    for msg in rsa_messages:
        ct_bytes = bytes.fromhex(msg['ciphertext'])
        ct = int.from_bytes(ct_bytes, 'little')
        
        pt = pow(ct, d, N)
        pt_bytes = pt.to_bytes((pt.bit_length() + 7) // 8, 'little').rstrip(b'\x00')
        
        try:
            plaintext = pt_bytes.decode('utf-8')
            print(f'    [+] "{plaintext}"')
            decrypted.append(plaintext)
        except:
            hex_str = pt_bytes.hex()
            print(f'    [+] [Hex: {hex_str}]')
            decrypted.append(hex_str)
    
    return decrypted

def main():
    print("="*70)
    print(" Chain of Demands - Recovery (Handles Gaps)")
    print("="*70)
    
    import sys
    if len(sys.argv) > 1:
        chat_log_path = sys.argv[1]
    else:
        chat_log_path = 'chat_log.json'
    
    with open(chat_log_path, 'r') as f:
        chat_log = json.load(f)
    
    print(f"\n[+] Loaded {len(chat_log)} messages")
    
    outputs, rounds = extract_outputs(chat_log)
    print(f"[+] Extracted {len(outputs)} LCG outputs")
    print(f"    Rounds: {rounds}")
    
    # Strategy 1: Mathematical solving with gaps
    lcg_params = solve_lcg_with_gaps(outputs, rounds)
    
    # Strategy 2: Brute force common primes
    if not lcg_params:
        print("\n[*] Mathematical approach failed, trying brute force...")
        m = outputs[0]  # Known from round 0
        lcg_params = brute_force_modulus(outputs, rounds, m)
    
    if not lcg_params:
        print("\n[-] Failed to recover LCG parameters")
        return
    
    seed, m, c, n = lcg_params
    
    print("\n" + "="*70)
    print(" LCG PARAMETERS RECOVERED")
    print("="*70)
    print(f"Seed:    {hex(seed)}")
    print(f"Multiplier m: {hex(m)}")
    print(f"Increment c:  {hex(c)}")
    print(f"Modulus n:    {hex(n)}")
    
    # Verify
    if not verify_lcg_operation(seed, m, c, n, outputs, rounds):
        print("\n[-] Verification failed!")
        return
    
    print("\n[+] LCG verification passed!")
    
    # Generate RSA primes and decrypt
    rsa_primes = generate_rsa_primes(seed, m, c, n)
    if not rsa_primes:
        return
    
    rsa_key = compute_rsa_key(rsa_primes)
    if not rsa_key:
        return
    
    decrypted = decrypt_rsa_messages(chat_log, rsa_key)
    
    # Save results
    results = {
        'seed': hex(seed),
        'lcg_params': {
            'multiplier': hex(m),
            'increment': hex(c),
            'modulus': hex(n)
        },
        'rsa_primes': [hex(p) for p in rsa_primes],
        'decrypted_messages': decrypted
    }
    
    with open('recovery_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    
    print("\n" + "="*70)
    print(" RECOVERY COMPLETE!")
    print("="*70)
    print(f"\n[+] Decrypted {len(decrypted)} messages")
    print("[+] Results saved to recovery_results.json")
    
    # Look for flag
    for msg in decrypted:
        if 'flag' in msg.lower() or 'flare' in msg.lower():
            print(f"\n🎯 POTENTIAL FLAG: {msg}")

if __name__ == '__main__':
    main()