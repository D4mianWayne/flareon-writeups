#!/usr/bin/env python3
"""
Unicorn Emulator for sub_140081760
Input: DX value, Output: Computed RAX value
Uses proper PE extraction like the original script
"""

from unicorn import *
from unicorn.x86_const import *
import struct
import pefile
import sys

# Memory layout (same as your script)
CODE_BASE = 0x140000000
CODE_SIZE = 0x2000000
STACK_BASE = 0x7FFFF0000000
STACK_SIZE = 0x100000
HEAP_BASE = 0x200000000
HEAP_SIZE = 0x100000

def extract_function_from_pe(pe_path, rva=0x81760, size=0x4000):
    """
    Extract function bytes directly from PE file - EXACTLY like your script
    """
    try:
        pe = pefile.PE(pe_path)
        
        # Find which section contains the RVA
        for section in pe.sections:
            section_start = section.VirtualAddress
            section_end = section_start + section.Misc_VirtualSize
            
            if section_start <= rva < section_end:
                # Calculate offset in section
                offset_in_section = rva - section_start
                raw_offset = section.PointerToRawData + offset_in_section
                
                # Read from file
                with open(pe_path, 'rb') as f:
                    f.seek(raw_offset)
                    data = f.read(size)
                
                section_name = section.Name.decode().rstrip('\x00')
                print(f"[+] Extracted {len(data)} bytes from {section_name}")
                print(f"    RVA: 0x{rva:x}, Raw offset: 0x{raw_offset:x}")
                
                return data
        
        print(f"[-] RVA 0x{rva:x} not found in any section")
        return None
        
    except Exception as e:
        print(f"[-] Error extracting from PE: {e}")
        return None

def emulate_dx_to_rax(dx_value, pe_path, verbose=False):
    """
    Emulate the function with proper PE loading
    """
    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        
        # Map memory - EXACTLY like your script
        mu.mem_map(CODE_BASE, CODE_SIZE)
        mu.mem_map(STACK_BASE, STACK_SIZE)
        mu.mem_map(HEAP_BASE, HEAP_SIZE)
        
        # Load the PE file properly
        print(f"[*] Loading PE file: {pe_path}")
        pe = pefile.PE(pe_path)
        
        # Load sections into memory - EXACTLY like your script
        for section in pe.sections:
            section_name = section.Name.decode().rstrip('\x00')
            section_data = section.get_data()
            virtual_addr = CODE_BASE + section.VirtualAddress
            
            print(f"    Section: {section_name:8s} @ 0x{virtual_addr:016x} "
                  f"(size: 0x{len(section_data):x})")
            
            # Write section data
            try:
                mu.mem_write(virtual_addr, section_data)
            except Exception as e:
                print(f"    [!] Failed to load {section_name}: {e}")
        
        # Setup stack pointer - EXACTLY like your script
        rsp_init = STACK_BASE + STACK_SIZE - 0x1000
        mu.reg_write(UC_X86_REG_RSP, rsp_init)
        mu.reg_write(UC_X86_REG_RBP, rsp_init)
        
        # Set function arguments - EXACTLY like your script
        arg1_ptr = HEAP_BASE + 0x1000  # Pointer to buffer/structure
        
        # Initialize the data structure at rcx - EXACTLY like your script
        # field_10: some 32-bit value
        mu.mem_write(arg1_ptr + 0x10, struct.pack('<I', 0xAABBCCDD))
        # field_20: PRNG state (64-bit)
        mu.mem_write(arg1_ptr + 0x20, struct.pack('<Q', 0x12345678ABCDEF00))
        
        # Set registers - EXACTLY like your script
        mu.reg_write(UC_X86_REG_RCX, arg1_ptr)  # First argument
        mu.reg_write(UC_X86_REG_DX, dx_value)   # Your input (second argument)
        
        # Setup return address - EXACTLY like your script
        ret_addr = 0xDEADBEEF
        mu.mem_write(rsp_init, struct.pack('<Q', ret_addr))
        
        if verbose:
            print(f"[+] Function setup:")
            print(f"    arg1 (RCX): 0x{arg1_ptr:016x} (structure pointer)")
            print(f"    arg2 (DX):  0x{dx_value:04x} (your input)")
            print(f"    Start:      0x{0x140081760:016x}")
            print(f"    Return:     0x{ret_addr:016x}")
        
        # Start emulation at the function
        start_addr = 0x140081760
        mu.emu_start(start_addr, ret_addr)
        
        # Get the result
        rax = mu.reg_read(UC_X86_REG_RAX)
        
        if verbose:
            # Read back modified structure
            field_10 = struct.unpack('<I', mu.mem_read(arg1_ptr + 0x10, 4))[0]
            field_20 = struct.unpack('<Q', mu.mem_read(arg1_ptr + 0x20, 8))[0]
            print(f"[+] Modified structure:")
            print(f"    field_10 = 0x{field_10:08x} (was 0xAABBCCDD)")
            print(f"    field_20 = 0x{field_20:016x} (was 0x12345678ABCDEF00)")
        
        return rax
        
    except UcError as e:
        print(f"[-] Emulation error: {e}")
        # Try to get partial result
        try:
            return mu.reg_read(UC_X86_REG_RAX)
        except:
            return None

def main():
    if len(sys.argv) < 3:
        print("Usage: python emulator.py <dx_value_hex> <pe_file> [--verbose]")
        print("Example: python emulator.py 1234 target.exe")
        print("Example: python emulator.py 1234 target.exe --verbose")
        sys.exit(1)
    
    # Parse arguments
    dx_value = int(sys.argv[1], 16) & 0xFFFF
    pe_file = sys.argv[2]
    verbose = "--verbose" in sys.argv
    
    print("=" * 60)
    print("Unicorn Emulator for sub_140081760")
    print("=" * 60)
    
    # Run emulation
    result = emulate_dx_to_rax(dx_value, pe_file, verbose)
    
    print("\n" + "=" * 60)
    if result is not None:
        print(f"RESULT: DX=0x{dx_value:04X} -> RAX=0x{result:016X}")
    else:
        print("EMULATION FAILED")
    print("=" * 60)

# Batch testing function using the same proper PE loading
def batch_test(pe_path, test_values=None):
    """Test multiple DX values with proper PE loading"""
    if test_values is None:
        test_values = [0x0000, 0x0001, 0x1234, 0x5678, 0xABCD, 0xFFFF]
    
    print("Batch test with proper PE loading:")
    print("DX      -> RAX")
    print("-" * 25)
    
    for dx in test_values:
        result = emulate_dx_to_rax(dx, pe_path, verbose=False)
        if result is not None:
            print(f"0x{dx:04X} -> 0x{result:016X}")
        else:
            print(f"0x{dx:04X} -> ERROR")

if __name__ == "__main__":
    main()
    
    # Uncomment for batch testing:
    # if len(sys.argv) > 2 and sys.argv[1] == "--batch":
    #     batch_test(sys.argv[2])