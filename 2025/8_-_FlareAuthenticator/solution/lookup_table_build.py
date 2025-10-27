#!/usr/bin/env python3
"""
Smart search strategy using lookup tables and optimization
"""

import itertools
from collections import defaultdict
import struct

def build_lookup_tables(emu, arg1_ptr):
    """
    Build lookup tables for all possible inputs
    
    For each position (1-25) and digit (0-9):
    - Store result of first run
    - Store result of second run
    """
    lookup = {
        'first': {},   # lookup['first'][position][digit] = result
        'second': {}   # lookup['second'][position][digit] = result
    }
    
    print("[*] Building lookup tables...")
    
    for position in range(1, 26):
        lookup['first'][position] = {}
        lookup['second'][position] = {}
        
        for digit in range(10):
            # First run
            arg2_first = position
            result_first = emu.emulate_function(arg1_ptr, arg2_first, silent=True)
            lookup['first'][position][digit] = result_first
            
            # Second run
            arg2_second = (position << 8) | (3 << 4) | digit
            result_second = emu.emulate_function(arg1_ptr, arg2_second, silent=True)
            lookup['second'][position][digit] = result_second
            
        print(f"  Position {position:2d}: Complete")
    
    print("[+] Lookup tables built!")
    return lookup

def compute_partial_result(digits, lookup, up_to_position):
    """
    Compute result using only first N digits
    """
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    val_78h = 0x0
    
    for i in range(up_to_position):
        position = i + 1
        digit = digits[i]
        
        first_val = lookup['first'][position][digit]
        second_val = lookup['second'][position][digit]
        
        if first_val is None or second_val is None:
            return None
        
        var_c78 = (first_val * second_val) & MASK_64
        val_78h = bitwise_operation(var_c78, val_78h)
    
    return val_78h

def bitwise_operation(var_c78, val_78h):
    """Copy from original code"""
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    r9 = var_c78 & MASK_64
    rdx = val_78h & MASK_64
    rcx = r9
    rcx = (~rcx) & MASK_64
    r8 = rdx
    r8 = (~r8) & MASK_64
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

def beam_search(lookup, target, beam_width=1000):
    """
    Beam search: Keep top N candidates at each position
    """
    print(f"[*] Starting beam search (width={beam_width})...")
    
    # Start with all possible first digits
    candidates = []
    for digit in range(10):
        candidates.append(([digit], compute_partial_result([digit], lookup, 1)))
    
    # For each subsequent position
    for position in range(2, 26):
        print(f"  Position {position}: {len(candidates)} candidates")
        
        new_candidates = []
        for digits, current_val in candidates:
            if current_val is None:
                continue
                
            # Try all 10 digits for next position
            for next_digit in range(10):
                new_digits = digits + [next_digit]
                new_val = compute_partial_result(new_digits, lookup, position)
                
                if new_val is not None:
                    # Calculate distance from target
                    # This is a heuristic - adjust as needed
                    distance = abs(new_val - target)
                    new_candidates.append((new_digits, new_val, distance))
        
        # Keep best candidates
        new_candidates.sort(key=lambda x: x[2])  # Sort by distance
        candidates = [(digits, val) for digits, val, _ in new_candidates[:beam_width]]
        
        # Check if we found it
        for digits, val in candidates:
            if val == target:
                print(f"[+] FOUND SOLUTION at position {position}!")
                return digits
    
    # Check final candidates
    for digits, val in candidates:
        if val == target:
            print("[+] FOUND SOLUTION!")
            return digits
    
    print("[-] No solution found")
    print(f"[*] Closest result: {candidates[0][1]:016x} (target: {target:016x})")
    print(f"[*] Digits: {candidates[0][0]}")
    return None

def meet_in_the_middle(lookup, target):
    """
    Meet-in-the-middle attack:
    - Compute all possibilities for first 12-13 digits
    - Compute all possibilities for last 12-13 digits (working backwards)
    - Find matches
    
    Note: This requires being able to reverse the operations
    """
    print("[*] Meet-in-the-middle approach")
    print("[!] Requires reversible operations - may not be applicable")
    print("[*] (Implementation placeholder)")
    
def genetic_algorithm(lookup, target, population_size=500, generations=10000):
    """
    Genetic algorithm approach
    """
    import random
    
    print(f"[*] Starting genetic algorithm (pop={population_size}, gen={generations})...")
    
    # Initialize population
    population = []
    for _ in range(population_size):
        digits = [random.randint(0, 9) for _ in range(25)]
        population.append(digits)
    
    best_ever = None
    best_distance = float('inf')
    
    for generation in range(generations):
        # Evaluate fitness
        fitness_scores = []
        for digits in population:
            result = compute_partial_result(digits, lookup, 25)
            if result is not None:
                distance = abs(result - target)
                fitness_scores.append((digits, result, distance))
                
                if distance < best_distance:
                    best_distance = distance
                    best_ever = (digits, result)
            else:
                fitness_scores.append((digits, None, float('inf')))
        
        # Check for solution
        for digits, result, distance in fitness_scores:
            if distance == 0:
                print(f"[+] FOUND SOLUTION at generation {generation}!")
                return digits
        
        # Sort by fitness
        fitness_scores.sort(key=lambda x: x[2])
        
        if generation % 100 == 0:
            print(f"  Gen {generation:5d}: Best distance = {fitness_scores[0][2]:016x}")
        
        # Selection: Keep top 50%
        population = [digits for digits, _, _ in fitness_scores[:population_size//2]]
        
        # Crossover and mutation
        while len(population) < population_size:
            parent1 = random.choice(population[:population_size//4])
            parent2 = random.choice(population[:population_size//4])
            
            # Crossover
            crossover_point = random.randint(1, 24)
            child = parent1[:crossover_point] + parent2[crossover_point:]
            
            # Mutation (10% chance per digit)
            child = [random.randint(0, 9) if random.random() < 0.1 else d for d in child]
            
            population.append(child)
    
    print(f"[-] No exact solution found")
    print(f"[*] Best result: {best_ever[1]:016x} (target: {target:016x})")
    print(f"[*] Best digits: {best_ever[0]}")
    return None

def main():
    print("=" * 70)
    print("Smart Search Strategies")
    print("=" * 70)
    print()
    print("Available strategies:")
    print("  1. Beam Search - Keep top N candidates at each step")
    print("  2. Genetic Algorithm - Evolutionary approach")
    print("  3. Meet-in-the-Middle - If operations are reversible")
    print()
    print("Usage:")
    print("  1. Build lookup tables first")
    print("  2. Choose and run a search strategy")
    print("=" * 70)

if __name__ == "__main__":
    main()