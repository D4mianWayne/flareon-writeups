#!/usr/bin/env python3
"""
Optimized solver using dynamic programming forward search

Key insight: At each position, there are only 10 possible digits.
We track ALL reachable states (val_78h values) efficiently.
"""

import sys
import struct
import pickle
import os
from collections import defaultdict

TARGET = 0x0BC42D5779FEC401

def bitwise_operation(var_c78, val_78h):
    """Forward bitwise operation"""
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    r9 = var_c78 & MASK_64
    rdx = val_78h & MASK_64
    rcx = (~r9) & MASK_64
    r8 = (~rdx) & MASK_64
    r8 = (r8 | rcx) & MASK_64
    rcx = rdx
    rcx = (rcx + r9) & MASK_64
    r8 = (r8 + rcx + 1) & MASK_64
    rdx = (rdx | r9) & MASK_64
    rcx = (rcx - rdx) & MASK_64
    rdx = rcx
    rdx = (rdx | r8) & MASK_64
    rcx = (rcx & r8) & MASK_64
    rcx = (rcx + rdx) & MASK_64
    return rcx

def dynamic_programming_solve(lookup, target):
    """
    Dynamic programming approach:
    - dp[position][val_78h] = list of digit sequences that produce val_78h
    
    This exhaustively explores the state space but prunes unreachable states.
    """
    print("\n[*] Starting dynamic programming solve...")
    print(f"[*] Target: 0x{target:016x}\n")
    
    # dp[val_78h] = list of digit sequences
    dp = {0: [[]]}  # Start with empty sequence producing 0
    
    for position in range(1, 26):
        next_dp = defaultdict(list)
        
        print(f"[Position {position:2d}/25] Current states: {len(dp):,}", end="")
        
        # Limit to prevent memory explosion
        if len(dp) > 500000:
            print(f" (pruning to best 500k)...", end="")
            # Keep states that seem most diverse or random sample
            import random
            items = list(dp.items())
            random.shuffle(items)
            dp = dict(items[:500000])
        
        state_count = 0
        
        for current_val, sequences in dp.items():
            # Limit sequences per state
            if len(sequences) > 100:
                sequences = sequences[:100]
            
            for digit in range(10):
                first_val = lookup['first'][position][digit]
                second_val = lookup['second'][position][digit]
                
                if first_val is not None and second_val is not None:
                    var_c78 = (first_val * second_val) & 0xFFFFFFFFFFFFFFFF
                    next_val = bitwise_operation(var_c78, current_val)
                    
                    state_count += 1
                    
                    # Check if we reached the target at final position
                    if position == 25 and next_val == target:
                        # Found it!
                        solution = sequences[0] + [digit]
                        print(f"\n\n[+] SOLUTION FOUND!")
                        return solution
                    
                    # Add to next states
                    for seq in sequences:
                        new_seq = seq + [digit]
                        next_dp[next_val].append(new_seq)
        
        dp = dict(next_dp)
        print(f" -> {len(dp):,} states, {state_count:,} transitions")
        
        # Early termination if no states
        if not dp:
            print("\n[-] No reachable states! Problem with lookup data?")
            return None
    
    # Check if target is reachable
    if target in dp:
        print(f"\n[+] Target found with {len(dp[target])} solutions!")
        return dp[target][0]
    else:
        print(f"\n[-] Target not reachable. Closest values:")
        # Find closest
        closest = sorted(dp.keys(), key=lambda x: abs(x - target))[:10]
        for val in closest:
            print(f"    0x{val:016x} (distance: 0x{abs(val - target):016x})")
        return None

def optimized_beam_search(lookup, target, beam_width=50000):
    """
    Optimized beam search that's more memory efficient
    """
    print(f"\n[*] Starting optimized beam search (beam={beam_width:,})...")
    print(f"[*] Target: 0x{target:016x}\n")
    
    # State: (val_78h, digit_sequence, distance_to_target)
    states = [(0, [], 0)]
    
    for position in range(1, 26):
        next_states = []
        
        print(f"[Position {position:2d}/25] States: {len(states):,} ", end="", flush=True)
        
        for current_val, digit_seq, _ in states:
            for digit in range(10):
                first_val = lookup['first'][position][digit]
                second_val = lookup['second'][position][digit]
                
                if first_val is not None and second_val is not None:
                    var_c78 = (first_val * second_val) & 0xFFFFFFFFFFFFFFFF
                    next_val = bitwise_operation(var_c78, current_val)
                    new_seq = digit_seq + [digit]
                    
                    if position == 25:
                        # Final position - check for exact match
                        if next_val == target:
                            print(f"\n\n[+] SOLUTION FOUND!")
                            return new_seq
                        # Still track best attempts
                        distance = abs(next_val - target)
                        next_states.append((next_val, new_seq, distance))
                    else:
                        # Not final position - use heuristic distance
                        distance = abs(next_val - target)
                        next_states.append((next_val, new_seq, distance))
        
        if not next_states:
            print("\n[-] No valid states!")
            return None
        
        # Sort by distance to target
        next_states.sort(key=lambda x: x[2])
        
        # Report best distance
        best_dist = next_states[0][2]
        print(f"-> Best distance: 0x{best_dist:016x}")
        
        # Keep only top beam_width states
        states = next_states[:beam_width]
    
    # Return best attempt
    print(f"\n[-] No exact match found")
    print(f"[*] Best result: 0x{states[0][0]:016x}")
    print(f"[*] Distance: 0x{states[0][2]:016x}")
    print(f"[*] Digits: {states[0][1]}")
    return None

def main():
    print("=" * 70)
    print("Optimized Forward Solver")
    print("=" * 70)
    
    if len(sys.argv) < 2:
        print("\nUsage: python reverse_solver.py binary.exe [--beam WIDTH]")
        print("\nMethods:")
        print("  default: Dynamic programming (exhaustive, memory-intensive)")
        print("  --beam N: Beam search with width N (faster, uses heuristics)")
        sys.exit(1)
    
    # Parse arguments
    use_beam = False
    beam_width = 50000
    
    for i, arg in enumerate(sys.argv):
        if arg == '--beam' and i + 1 < len(sys.argv):
            use_beam = True
            beam_width = int(sys.argv[i + 1])
    
    # Load emulator and build lookup table
    from unicorn_emulation_3 import FunctionEmulator, HEAP_BASE
    
    emu = FunctionEmulator()
    if not emu.load_pe_file(sys.argv[1]):
        print("[-] Failed to load PE file")
        sys.exit(1)
    
    arg1_ptr = HEAP_BASE + 0x1000
    test_buffer = struct.pack('<Q', 0x4141414141414141) * 32
    emu.mu.mem_write(arg1_ptr, test_buffer)
    
    # Build lookup table
    cache_file = 'lookup_cache.pkl'
    if os.path.exists(cache_file):
        print(f"\n[*] Loading cached lookup tables from {cache_file}")
        with open(cache_file, 'rb') as f:
            lookup = pickle.load(f)
    else:
        print("\n[*] Building lookup tables...")
        lookup = {'first': {}, 'second': {}}
        for position in range(1, 26):
            lookup['first'][position] = {}
            lookup['second'][position] = {}
            for digit in range(10):
                arg2_first = position
                result_first = emu.emulate_function(arg1_ptr, arg2_first, silent=True)
                lookup['first'][position][digit] = result_first
                
                arg2_second = (position << 8) | (3 << 4) | digit
                result_second = emu.emulate_function(arg1_ptr, arg2_second, silent=True)
                lookup['second'][position][digit] = result_second
            print(f"  Position {position}/25")
        
        with open(cache_file, 'wb') as f:
            pickle.dump(lookup, f)
    
    # Solve
    if use_beam:
        solution = optimized_beam_search(lookup, TARGET, beam_width)
    else:
        solution = dynamic_programming_solve(lookup, TARGET)
    
    if solution:
        print("\n" + "=" * 70)
        print("SOLUTION FOUND!")
        print("=" * 70)
        print(f"\nDigits: {solution}")
        print(f"Length: {len(solution)}")
        print(f"\nAs comma-separated: {','.join(map(str, solution))}")
        
        # Verify
        print("\n[*] Verifying...")
        val_78h = 0
        MASK_64 = 0xFFFFFFFFFFFFFFFF
        for i, digit in enumerate(solution):
            position = i + 1
            first_val = lookup['first'][position][digit]
            second_val = lookup['second'][position][digit]
            var_c78 = (first_val * second_val) & MASK_64
            val_78h = bitwise_operation(var_c78, val_78h)
        
        print(f"Result: 0x{val_78h:016x}")
        print(f"Target: 0x{TARGET:016x}")
        print(f"Match: {'YES! ✓' if val_78h == TARGET else 'NO ✗'}")
    else:
        print("\n[-] No solution found")

if __name__ == "__main__":
    main()