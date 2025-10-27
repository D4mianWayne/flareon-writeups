#!/usr/bin/env python3
"""
Unicorn Emulator for sub_140081760
Windows x64 binary - Heavily obfuscated function
Enhanced to test series of digits with dual-run methodology
"""

from unicorn import *
from unicorn.x86_const import *
import struct
import pefile
import sys

# Memory layout (Windows x64 style)
CODE_BASE = 0x140000000          # Typical Windows x64 image base
CODE_SIZE = 0x2000000            # 32MB for entire PE (code + data)
STACK_BASE = 0x7FFFF0000000      # High address for stack
STACK_SIZE = 0x100000            # 1MB stack
HEAP_BASE = 0x200000000          # Heap for allocations
HEAP_SIZE = 0x100000             # 1MB heap

class FunctionEmulator:
    def __init__(self, pe_path=None):
        self.mu = Uc(UC_ARCH_X86, UC_MODE_64)
        self.pe_path = pe_path
        self.pe = None
        self.setup_memory()
        self.setup_hooks()
        self.call_count = 0
        self.trace_instructions = False  # Set to True for detailed trace
        
    def setup_memory(self):
        """Setup memory regions for Windows x64"""
        # Code segment (entire PE image - includes .text, .data, .rdata, etc.)
        self.mu.mem_map(CODE_BASE, CODE_SIZE)
        
        # Stack (grows down)
        self.mu.mem_map(STACK_BASE, STACK_SIZE)
        
        # Heap for dynamic allocations
        self.mu.mem_map(HEAP_BASE, HEAP_SIZE)
        
        print(f"[+] Memory mapped:")
        print(f"    PE Image: 0x{CODE_BASE:016x} - 0x{CODE_BASE + CODE_SIZE:016x}")
        print(f"    Stack:    0x{STACK_BASE:016x} - 0x{STACK_BASE + STACK_SIZE:016x}")
        print(f"    Heap:     0x{HEAP_BASE:016x} - 0x{HEAP_BASE + HEAP_SIZE:016x}")
        
    def setup_hooks(self):
        """Setup emulation hooks"""
        self.mu.hook_add(UC_HOOK_CODE, self.hook_code)
        self.mu.hook_add(UC_HOOK_MEM_UNMAPPED, self.hook_mem_unmapped)
        self.mu.hook_add(UC_HOOK_INTR, self.hook_interrupt)
        self.mu.hook_add(UC_HOOK_INSN_INVALID, self.hook_invalid_insn)
        
    def hook_code(self, uc, address, size, user_data):
        """Code execution hook for tracing"""
        try:
            # Only trace if enabled or at key addresses
            if self.trace_instructions or address in [0x140081760, 0x14008259E, 0x14008264B]:
                code = uc.mem_read(address, min(size, 15))
                rax = uc.reg_read(UC_X86_REG_RAX)
                rcx = uc.reg_read(UC_X86_REG_RCX)
                rdx = uc.reg_read(UC_X86_REG_RDX)
                r8 = uc.reg_read(UC_X86_REG_R8)
                
                # Check for dispatcher (state machine)
                rsp = uc.reg_read(UC_X86_REG_RSP)
                if address == 0x14008259E:  # Main dispatcher
                    try:
                        dispatcher_val = struct.unpack('<I', uc.mem_read(rsp + 0x578 - 0x39C, 4))[0]
                        print(f"[DISPATCH] State: 0x{dispatcher_val:08x}")
                    except:
                        pass
                
                print(f"[0x{address:016x}] {code.hex()[:20]:20s} | "
                      f"RAX={rax:016x} RCX={rcx:016x} RDX={rdx:016x}")
        except:
            pass
    
    def hook_invalid_insn(self, uc, user_data):
        """Handle invalid instruction"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        try:
            code = uc.mem_read(rip, 16)
            print(f"[!] Invalid instruction at 0x{rip:016x}: {code.hex()}")
        except:
            print(f"[!] Invalid instruction at 0x{rip:016x}")
        return False
            
    def hook_mem_unmapped(self, uc, access, address, size, value, user_data):
        """Handle unmapped memory access"""
        access_type = {
            UC_MEM_WRITE: "WRITE",
            UC_MEM_READ: "READ",
            UC_MEM_FETCH: "FETCH"
        }.get(access, "UNKNOWN")
        
        print(f"[!] Unmapped memory access: {access_type} at 0x{address:016x}, size={size}")
        
        # Try to map the page dynamically
        page_size = 0x1000
        page_base = address & ~(page_size - 1)
        
        try:
            self.mu.mem_map(page_base, page_size)
            print(f"[+] Dynamically mapped: 0x{page_base:016x} - 0x{page_base + page_size:016x}")
            return True
        except:
            print(f"[-] Failed to map memory at 0x{page_base:016x}")
            return False
            
    def hook_interrupt(self, uc, intno, user_data):
        """Handle interrupts (like int3/icebp)"""
        rip = uc.reg_read(UC_X86_REG_RIP)
        print(f"[!] Interrupt {intno} at 0x{rip:016x}")
        
        # Skip the interrupt instruction
        if intno == 1:  # ICEBP
            uc.reg_write(UC_X86_REG_RIP, rip + 1)
            
    def load_pe_file(self, pe_path):
        """Load PE file and extract necessary sections"""
        print(f"[*] Loading PE file: {pe_path}")
        
        try:
            self.pe = pefile.PE(pe_path)
            
            # Load sections into memory
            for section in self.pe.sections:
                section_name = section.Name.decode().rstrip('\x00')
                section_data = section.get_data()
                virtual_addr = CODE_BASE + section.VirtualAddress
                
                print(f"    Section: {section_name:8s} @ 0x{virtual_addr:016x} "
                      f"(size: 0x{len(section_data):x})")
                
                # Write section data
                try:
                    self.mu.mem_write(virtual_addr, section_data)
                except Exception as e:
                    print(f"    [!] Failed to load {section_name}: {e}")
            
            # Load import directory data if needed
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                print("[*] PE has imports (not emulating Windows APIs)")
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to load PE: {e}")
            return False
    
    def load_function_code(self, code_bytes, base_addr=0x140081760):
        """Load raw function code into emulator"""
        offset = base_addr - CODE_BASE
        self.mu.mem_write(CODE_BASE + offset, code_bytes)
        print(f"[+] Loaded {len(code_bytes)} bytes at 0x{base_addr:016x}")
        
    def emulate_function(self, arg1_rcx, arg2_dx, max_instructions=100000, silent=False):
        """
        Emulate the function with given arguments
        
        Args:
            arg1_rcx: First argument (pointer to data structure)
            arg2_dx: Second argument (word value, shift key)
            max_instructions: Maximum instructions to execute
            silent: If True, suppress detailed output
        """
        if not silent:
            print(f"\n[*] Starting emulation...")
            print(f"    arg1 (RCX): 0x{arg1_rcx:016x} (pointer to structure)")
            print(f"    arg2 (DX):  0x{arg2_dx:04x} (shift key)")
        
        # Setup registers
        rsp_init = STACK_BASE + STACK_SIZE - 0x1000
        self.mu.reg_write(UC_X86_REG_RSP, rsp_init)
        self.mu.reg_write(UC_X86_REG_RBP, rsp_init)
        
        # Set function arguments
        self.mu.reg_write(UC_X86_REG_RCX, arg1_rcx)
        self.mu.reg_write(UC_X86_REG_DX, arg2_dx)
        
        # Setup return address (will trigger stop)
        ret_addr = 0xDEADBEEF
        self.mu.mem_write(rsp_init, struct.pack('<Q', ret_addr))
        
        # Initialize the data structure at rcx
        if arg1_rcx >= HEAP_BASE and arg1_rcx < HEAP_BASE + HEAP_SIZE:
            # field_10: some 32-bit value
            self.mu.mem_write(arg1_rcx + 0x10, struct.pack('<I', 0xAABBCCDD))
            # field_20: PRNG state (64-bit)
            self.mu.mem_write(arg1_rcx + 0x20, struct.pack('<Q', 0x12345678ABCDEF00))
            if not silent:
                print(f"[+] Initialized structure at 0x{arg1_rcx:016x}")
        
        try:
            # Start emulation
            start_addr = 0x140081760
            self.mu.emu_start(start_addr, ret_addr, count=max_instructions)
            
            # Get results
            rax = self.mu.reg_read(UC_X86_REG_RAX)
            if not silent:
                print(f"\n[+] Emulation completed")
                print(f"    Return value (RAX): 0x{rax:016x} ({rax})")
            
            return rax
            
        except UcError as e:
            if not silent:
                rip = self.mu.reg_read(UC_X86_REG_RIP)
                rax = self.mu.reg_read(UC_X86_REG_RAX)
                print(f"\n[-] Emulation error: {e}")
                print(f"    RIP: 0x{rip:016x}")
                print(f"    RAX: 0x{rax:016x}")
            
            return None

def run_digit_series(emu, digit_array, arg1_ptr):
    """
    Run emulation for a series of digits using two different methods
    
    Method 1 (First Run): Use digit directly as 0x<digit>
    Method 2 (Second Run): Use 0x<index_hex><digit_hex> format
    
    Args:
        emu: FunctionEmulator instance
        digit_array: Array of 25 single digits (0-9)
        arg1_ptr: Pointer to heap buffer
    
    Returns:
        dict with results from both runs
    """
    
    if len(digit_array) != 25:
        print(f"[!] Warning: Expected 25 digits, got {len(digit_array)}")
    
    results = {
        'first_run': [],   # Simple format: 0x<digit>
        'second_run': []   # Indexed format: 0x<index_hex><digit_hex>
    }
    
    print("\n" + "=" * 70)
    print("FIRST RUN - Simple Format (0x<index>)")
    print("=" * 70)
    
    for i, digit in enumerate(digit_array, 1):
        if digit < 0 or digit > 9:
            print(f"[!] Invalid digit {digit} at position {i}, skipping")
            continue
        
        arg2_val = i  # Use position/index as input
        print(f"\n[Run 1.{i:02d}] Position {i:02d}, Digit {digit} -> arg2 = 0x{arg2_val:x}")
        
        result = emu.emulate_function(arg1_ptr, arg2_val, silent=True)
        results['first_run'].append({
            'position': i,
            'digit': digit,
            'arg2': arg2_val,
            'result': result
        })
        
        if result is not None:
            print(f"         Result: 0x{result:016x} ({result})")
        else:
            print(f"         Result: FAILED")
    
    print("\n" + "=" * 70)
    print("SECOND RUN - Indexed Format (0x<index_hex><digit_hex>)")
    print("=" * 70)
    
    for i, digit in enumerate(digit_array, 1):
        if digit < 0 or digit > 9:
            continue
        
        # Format: 0x<index_hex>3<digit_hex>
        # Example: position 1, digit 1 -> 0x131
        # Example: position 14, digit 4 -> 0xE34
        arg2_val = (i << 8) | (3 << 4) | digit
        
        print(f"\n[Run 2.{i:02d}] Position {i:02d}, Digit {digit} -> arg2 = 0x{arg2_val:03x}")
        
        result = emu.emulate_function(arg1_ptr, arg2_val, silent=True)
        results['second_run'].append({
            'position': i,
            'digit': digit,
            'arg2': arg2_val,
            'result': result
        })
        
        if result is not None:
            print(f"         Result: 0x{result:016x} ({result})")
        else:
            print(f"         Result: FAILED")
    
    return results

def bitwise_operation(var_c78, val_78h):
    """
    Reproduces the assembly operations
    
    Args:
        var_c78: Value from var_C78 (r9)
        val_78h: Value from [rax+78h] (rdx)
    
    Returns:
        The final result stored back to [rax+78h]
    """
    # Mask to keep values as 64-bit unsigned
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    
    # Initial values
    r9 = var_c78 & MASK_64
    rdx = val_78h & MASK_64
    
    # mov rcx, r9
    rcx = r9
    
    # not rcx
    rcx = (~rcx) & MASK_64
    
    # mov r8, rdx
    r8 = rdx
    
    # not r8
    r8 = (~r8) & MASK_64
    
    # or r8, rcx
    r8 = (r8 | rcx) & MASK_64
    
    # mov rcx, rdx
    rcx = rdx
    
    # add rcx, r9
    rcx = (rcx + r9) & MASK_64
    
    # lea r8, [r8+rcx+1]
    r8 = (r8 + rcx + 1) & MASK_64
    
    # or rdx, r9
    rdx = (rdx | r9) & MASK_64
    
    # sub rcx, rdx
    rcx = (rcx - rdx) & MASK_64
    
    # mov rdx, rcx
    rdx = rcx
    
    # or rdx, r8
    rdx = (rdx | r8) & MASK_64
    
    # and rcx, r8
    rcx = (rcx & r8) & MASK_64
    
    # add rcx, rdx
    rcx = (rcx + rdx) & MASK_64
    
    return rcx


def compute_final_result(results):
    """
    Combine results from both runs using imul and bitwise operations
    
    Args:
        results: Dictionary with 'first_run' and 'second_run' lists
    
    Returns:
        Final val_78h value after all iterations
    """
    print("\n" + "=" * 70)
    print("COMPUTING FINAL RESULT")
    print("=" * 70)
    
    # Mask for 64-bit signed multiplication result
    MASK_64 = 0xFFFFFFFFFFFFFFFF
    
    # Initialize val_78h to 0
    val_78h = 0x0
    
    print(f"\nInitial val_78h: 0x{val_78h:016x}")
    print("\n" + "-" * 70)
    
    # Process each pair of results
    num_pairs = min(len(results['first_run']), len(results['second_run']))
    
    for i in range(num_pairs):
        first_val = results['first_run'][i]['result']
        second_val = results['second_run'][i]['result']
        position = results['first_run'][i]['position']
        digit = results['first_run'][i]['digit']
        
        if first_val is None or second_val is None:
            print(f"\n[Step {i+1}] Position {position}: SKIPPED (failed result)")
            continue
        
        # Perform imul (signed 64-bit multiplication, take lower 64 bits)
        var_c78 = (first_val * second_val) & MASK_64
        
        print(f"\n[Step {i+1}] Position {position}, Digit {digit}:")
        print(f"  First run result:  0x{first_val:016x} ({first_val})")
        print(f"  Second run result: 0x{second_val:016x} ({second_val})")
        print(f"  imul result (var_c78): 0x{var_c78:016x}")
        print(f"  Previous val_78h: 0x{val_78h:016x}")
        
        # Apply bitwise operation
        val_78h = bitwise_operation(var_c78, val_78h)
        
        print(f"  New val_78h: 0x{val_78h:016x}")
    
    print("\n" + "=" * 70)
    print(f"FINAL RESULT: 0x{val_78h:016x} ({val_78h})")
    print("=" * 70)
    
    return val_78h


def print_results_summary(results, digit_array):
    """Print a summary of all results"""
    print("\n" + "=" * 70)
    print("RESULTS SUMMARY")
    print("=" * 70)
    
    print("\n--- First Run (Simple Format) ---")
    print(f"{'Pos':>4} {'Digit':>5} {'arg2':>8} {'Result':>18}")
    print("-" * 40)
    for r in results['first_run']:
        result_str = f"0x{r['result']:016x}" if r['result'] is not None else "FAILED"
        print(f"{r['position']:>4} {r['digit']:>5} {r['arg2']:>#8x} {result_str:>18}")
    
    print("\n--- Second Run (Indexed Format) ---")
    print(f"{'Pos':>4} {'Digit':>5} {'arg2':>8} {'Result':>18}")
    print("-" * 40)
    for r in results['second_run']:
        result_str = f"0x{r['result']:016x}" if r['result'] is not None else "FAILED"
        print(f"{r['position']:>4} {r['digit']:>5} {r['arg2']:>#8x} {result_str:>18}")
    
    # Print digit array for reference
    print("\n--- Input Digit Array ---")
    print("Position: ", end="")
    for i in range(1, 26):
        print(f"{i:>3}", end="")
    print("\nDigit:    ", end="")
    for d in digit_array:
        print(f"{d:>3}", end="")
    print()

def main():
    print("=" * 70)
    print("Enhanced Unicorn Emulator - Digit Series Testing")
    print("Function: sub_140081760")
    print("=" * 70)
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  python script.py binary.exe [digit_array]")
        print("\nExample with custom digits:")
        print("  python script.py binary.exe 1,2,3,4,5,6,7,8,9,8,7,6,5,4,3,2,1,0,1,2,3,4,5,6,7")
        print("\nExample with default test array:")
        print("  python script.py binary.exe")
        sys.exit(1)
    
    emu = FunctionEmulator()
    
    # Load binary
    if "--raw" in sys.argv:
        with open(sys.argv[1], 'rb') as f:
            code = f.read()
        emu.load_function_code(code)
    else:
        if not emu.load_pe_file(sys.argv[1]):
            print("[-] Failed to load PE file")
            sys.exit(1)
    
    # Parse digit array from command line or use default
    if len(sys.argv) >= 3 and '--raw' not in sys.argv[2]:
        digit_str = sys.argv[2]
        digit_array = [int(d.strip()) for d in digit_str.split(',')]
    else:
        # Default test array: 1-9, then 9-1, then 1-7
        digit_array = [1, 2, 3, 4, 5, 6, 7, 8, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6, 7]
    
    print(f"\n[*] Testing with {len(digit_array)} digits: {digit_array}")
    
    # Validate digit array
    if len(digit_array) != 25:
        print(f"[!] Warning: Expected 25 digits, got {len(digit_array)}")
        if len(digit_array) < 25:
            print("[*] Padding with zeros...")
            digit_array.extend([0] * (25 - len(digit_array)))
        else:
            print("[*] Truncating to 25 digits...")
            digit_array = digit_array[:25]
    
    # Setup test arguments
    arg1_ptr = HEAP_BASE + 0x1000
    test_buffer = struct.pack('<Q', 0x4141414141414141) * 32
    emu.mu.mem_write(arg1_ptr, test_buffer)
    
    # Run the digit series
    results = run_digit_series(emu, digit_array, arg1_ptr)
    
    # Compute final result using imul and bitwise operations
    final_result = compute_final_result(results)
    
    # Print summary
    print_results_summary(results, digit_array)
    
    print("\n" + "=" * 70)
    print("[*] Digit series testing complete!")
    print(f"[*] Final computed value: 0x{final_result:016x}")
    print("=" * 70)

if __name__ == "__main__":
    main()