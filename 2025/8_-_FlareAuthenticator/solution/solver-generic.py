#!/usr/bin/env python3
"""
Reverse Solver for sub_140081760
Given a target value, find the 25-digit sequence that produces it
"""

import itertools
import struct
import sys
from unicorn import *
from unicorn.x86_const import *

# Memory layout (same as before)
CODE_BASE = 0x140000000
CODE_SIZE = 0x2000000
STACK_BASE = 0x7FFFF0000000
STACK_SIZE = 0x100000
HEAP_BASE = 0x200000000
HEAP_SIZE = 0x100000

class ReverseSolver:
    def __init__(self, pe_path):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pe_path = pe_path
        self.setup_memory()
        self.setup_hooks()
        
    def setup_memory(self):
        """Setup memory regions"""
        self.mu.mem_map(CODE_BASE, CODE_SIZE)
        self.mu.mem_map(STACK_BASE, STACK_SIZE)
        self.mu.mem_map(HEAP_BASE, HEAP_SIZE)
        
    def setup_hooks(self):
        """Setup minimal hooks for performance"""
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_mem_unmapped)
        
    def hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory access"""
        page_size = 0x1000
        page_base = address & ~(page_size - 1)
        try:
            self.mu.mem_map(page_base, page_size)
            return True
        except:
            return False
    
    def load_pe_file(self):
        """Load PE file"""
        import pefile
        try:
            pe = pefile.PE(self.pe_path)
            for section in pe.sections:
                section_data = section.get_data()
                virtual_addr = CODE_BASE + section.VirtualAddress
                self.mu.mem_write(virtual_addr, section_data)
            return True
        except Exception as e:
            print(f"[-] Failed to load PE: {e}")
            return False
    
    def emulate_single_digit(self, arg1_ptr, position, digit, run_type):
        """
        Emulate function for a single digit
        
        Args:
            arg1_ptr: Pointer to data structure
            position: Digit position (1-25)
            digit: Digit value (0-9)
            run_type: 1 for first run, 2 for second run
            
        Returns:
            Result value or None if failed
        """
        # Setup stack and registers
        rsp_init = STACK_BASE + STACK_SIZE - 0x1000
        self.mu.reg_write(UC_X86_REG_RSP, rsp_init)
        self.mu.reg_write(UC_X86_REG_RBP, rsp_init)
        
        # Set return address
        ret_addr = 0xDEADBEEF
        self.mu.mem_write(rsp_init, struct.pack('<Q', ret_addr))
        
        # Initialize structure
        self.mu.mem_write(arg1_ptr + 0x10, struct.pack('<I', 0xAABBCCDD))
        self.mu.mem_write(arg1_ptr + 0x20, struct.pack('<Q', 0x12345678ABCDEF00))
        
        # Set arguments based on run type
        self.mu.reg_write(UC_X86_REG_RCX, arg1_ptr)
        
        if run_type == 1:
            # First run: simple format
            arg2_val = position
        else:
            # Second run: indexed format
            arg2_val = (position << 8) | (3 << 4) | digit
        
        self.mu.reg_write(UC_X86_REG_DX, arg2_val)
        
        try:
            self.mu.emu_start(0x140081760, ret_addr, count=50000)
            return self.mu.reg_read(UC_X86_REG_RAX)
        except UcError:
            return None

    def compute_final_for_digits(self, digits):
        """
        Compute final value for given digit sequence
        """
        arg1_ptr = HEAP_BASE + 0x1000
        test_buffer = struct.pack('<Q', 0x4141414141414141) * 32
        self.mu.mem_write(arg1_ptr, test_buffer)
        
        results = {'first_run': [], 'second_run': []}
        
        # Run for all digits
        for i, digit in enumerate(digits, 1):
            # First run
            result1 = self.emulate_single_digit(arg1_ptr, i, digit, 1)
            results['first_run'].append(result1)
            
            # Second run  
            result2 = self.emulate_single_digit(arg1_ptr, i, digit, 2)
            results['second_run'].append(result2)
        
        # Compute final result
        return self.combine_results(results)

    def combine_results(self, results):
        """
        Combine results using the bitwise operation chain
        """
        MASK_64 = 0xFFFFFFFFFFFFFFFF
        val_78h = 0x0
        
        for i in range(len(results['first_run'])):
            if results['first_run'][i] is None or results['second_run'][i] is None:
                continue
                
            first_val = results['first_run'][i]
            second_val = results['second_run'][i]
            
            # imul operation
            var_c78 = (first_val * second_val) & MASK_64
            
            # Bitwise operation chain
            val_78h = self.bitwise_operation(var_c78, val_78h)
            
        return val_78h

    def bitwise_operation(self, var_c78, val_78h):
        """The bitwise operation from the assembly"""
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

def brute_force_solve(solver, target_value, max_attempts=1000000):
    """
    Brute force approach to find digits that match target
    """
    print(f"[*] Searching for digits that produce: 0x{target_value:016x}")
    print("[*] This may take a while...")
    
    attempts = 0
    digits_tested = 0
    
    # Try random digit sequences
    import random
    while attempts < max_attempts:
        digits = [random.randint(0, 9) for _ in range(25)]
        result = solver.compute_final_for_digits(digits)
        
        attempts += 1
        digits_tested += 25
        
        if attempts % 1000 == 0:
            print(f"[*] Tested {attempts} sequences ({digits_tested} digits)...")
        
        if result == target_value:
            print(f"\n[+] FOUND MATCH after {attempts} attempts!")
            print(f"Digits: {digits}")
            return digits
    
    print(f"[-] No match found after {attempts} attempts")
    return None

def targeted_search(solver, target_value, known_positions=None):
    """
    More targeted search if we know some digits
    """
    if known_positions is None:
        # If we know nothing, start with common patterns
        common_patterns = [
            [1,2,3,4,5,6,7,8,9,8,7,6,5,4,3,2,1,0,9,8,7,6,5,4,3],
            [1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5],
            [0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,6,7,8,9,0,1,2,3,4],
            [9,8,7,6,5,4,3,2,1,0,9,8,7,6,5,4,3,2,1,0,9,8,7,6,5],
        ]
        
        for pattern in common_patterns:
            result = solver.compute_final_for_digits(pattern)
            if result == target_value:
                return pattern
    
    return None

def analyze_operation_properties():
    """
    Analyze mathematical properties to optimize search
    """
    print("[*] Analyzing operation properties...")
    
    # The operation appears to be a complex bitwise function
    # Key observations:
    # 1. Each digit contributes independently but position matters
    # 2. The operation is deterministic
    # 3. Small changes in input create complex changes in output
    
    print("Properties:")
    print("- Each position 1-25 contributes differently")
    print("- Operation uses both multiplication and complex bitwise ops")
    print("- The function appears to be a custom hash/checksum")
    print("- Reversing mathematically would be very difficult")
    print("- Brute force is most practical approach")

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python reverse_solver.py binary.exe TARGET_VALUE")
        print("\nExamples:")
        print("  python reverse_solver.py binary.exe 0x123456789ABCDEF0")
        print("  python reverse_solver.py binary.exe 123456789")
        sys.exit(1)
    
    # Parse target value
    target_str = sys.argv[2]
    if target_str.startswith('0x'):
        target_value = int(target_str, 16)
    else:
        target_value = int(target_str)
    
    print("=" * 70)
    print("Reverse Solver for sub_140081760")
    print(f"Target: 0x{target_value:016x} ({target_value})")
    print("=" * 70)
    
    # Initialize solver
    solver = ReverseSolver(sys.argv[1])
    
    if not solver.load_pe_file():
        print("[-] Failed to load PE file")
        sys.exit(1)
    
    # Analyze the operation
    analyze_operation_properties()
    
    # Try targeted search first
    print("\n[*] Attempting targeted search...")
    result = targeted_search(solver, target_value)
    
    if result:
        print(f"\n[+] Found via targeted search!")
        print(f"Digits: {result}")
        
        # Verify
        verification = solver.compute_final_for_digits(result)
        print(f"Verification: 0x{verification:016x} (matches: {verification == target_value})")
    else:
        print("[-] Targeted search failed, starting brute force...")
        
        # Start brute force
        digits = brute_force_solve(solver, target_value, max_attempts=100000)
        
        if digits:
            print(f"\n[+] Solution found!")
            print(f"Digit sequence: {digits}")
            
            # Format for easy use
            digit_str = ','.join(map(str, digits))
            print(f"Formatted: {digit_str}")
        else:
            print(f"\n[-] No solution found with brute force")
            print("[*] Try increasing max_attempts or analyze the function more deeply")

if __name__ == "__main__":
    main()