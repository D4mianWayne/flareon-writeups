#!/usr/bin/env python3
"""
Unicorn Emulator for sub_140081760
Windows x64 binary - Heavily obfuscated function
Arguments: rcx (qword ptr), dx (word)
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
        
    def emulate_function(self, arg1_rcx, arg2_dx, max_instructions=100000):
        """
        Emulate the function with given arguments
        
        Args:
            arg1_rcx: First argument (pointer to data structure)
            arg2_dx: Second argument (word value, shift key)
            max_instructions: Maximum instructions to execute
        """
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
        # Based on analysis: structure has fields at +0x10 and +0x20
        if arg1_rcx >= HEAP_BASE and arg1_rcx < HEAP_BASE + HEAP_SIZE:
            # field_10: some 32-bit value
            self.mu.mem_write(arg1_rcx + 0x10, struct.pack('<I', 0xAABBCCDD))
            # field_20: PRNG state (64-bit)
            self.mu.mem_write(arg1_rcx + 0x20, struct.pack('<Q', 0x12345678ABCDEF00))
            print(f"[+] Initialized structure at 0x{arg1_rcx:016x}")
            print(f"    field_10 = 0xAABBCCDD")
            print(f"    field_20 = 0x12345678ABCDEF00")
        
        try:
            # Start emulation
            start_addr = 0x140081760
            self.mu.emu_start(start_addr, ret_addr, count=max_instructions)
            
            # Get results
            rax = self.mu.reg_read(UC_X86_REG_RAX)
            print(f"\n[+] Emulation completed")
            print(f"    Return value (RAX): 0x{rax:016x} ({rax})")
            
            # Read back modified structure
            if arg1_rcx >= HEAP_BASE and arg1_rcx < HEAP_BASE + HEAP_SIZE:
                field_10 = struct.unpack('<I', self.mu.mem_read(arg1_rcx + 0x10, 4))[0]
                field_20 = struct.unpack('<Q', self.mu.mem_read(arg1_rcx + 0x20, 8))[0]
                print(f"\n[+] Modified structure:")
                print(f"    field_10 = 0x{field_10:08x} (was 0xAABBCCDD)")
                print(f"    field_20 = 0x{field_20:016x} (was 0x12345678ABCDEF00)")
            
            return rax
            
        except UcError as e:
            rip = self.mu.reg_read(UC_X86_REG_RIP)
            rax = self.mu.reg_read(UC_X86_REG_RAX)
            rcx = self.mu.reg_read(UC_X86_REG_RCX)
            rdx = self.mu.reg_read(UC_X86_REG_RDX)
            rsp = self.mu.reg_read(UC_X86_REG_RSP)
            
            print(f"\n[-] Emulation error: {e}")
            print(f"    RIP: 0x{rip:016x}")
            print(f"    RAX: 0x{rax:016x}")
            print(f"    RCX: 0x{rcx:016x}")
            print(f"    RDX: 0x{rdx:016x}")
            print(f"    RSP: 0x{rsp:016x}")
            
            return None

def load_binary_from_file(filepath):
    """Load binary function from file"""
    with open(filepath, 'rb') as f:
        return f.read()

def extract_function_from_pe(pe_path, rva=0x81760, size=0x4000):
    """
    Extract function bytes directly from PE file
    
    Args:
        pe_path: Path to PE file
        rva: Relative Virtual Address of function
        size: Approximate size to extract
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

def main():
    print("=" * 70)
    print("Unicorn Emulator for Windows x64 Binary")
    print("Function: sub_140081760")
    print("Obfuscation: Control Flow Flattening + Junk Code")
    print("=" * 70)
    
    if len(sys.argv) < 2:
        print("\nUsage:")
        print("  Method 1 - Load full PE:")
        print("    python script.py binary.exe")
        print("\n  Method 2 - Load extracted bytes:")
        print("    python script.py func.bin --raw")
        print("\n  Method 3 - Interactive mode:")
        print("    python script.py --interactive")
        sys.exit(1)
    
    emu = FunctionEmulator()
    
    # Load binary
    if sys.argv[1] == "--interactive":
        print("\n[*] Interactive mode - manual setup required")
        print("    Modify the script to load your binary")
    elif "--raw" in sys.argv:
        # Load raw bytes
        with open(sys.argv[1], 'rb') as f:
            code = f.read()
        emu.load_function_code(code)
    else:
        # Load PE file
        if not emu.load_pe_file(sys.argv[1]):
            print("[-] Failed to load PE file")
            sys.exit(1)
    
    print("\n" + "=" * 70)
    print("Setting up test case")
    print("=" * 70)
    
    # Setup test arguments
    arg1_ptr = HEAP_BASE + 0x1000  # Pointer to buffer
    arg2_val = 0x732               # 16-bit value
    
    # Prepare heap buffer with test data
    test_buffer = struct.pack('<Q', 0x4141414141414141) * 32
    emu.mu.mem_write(arg1_ptr, test_buffer)
    
    print(f"[*] arg1 (RCX): 0x{arg1_ptr:016x} -> points to heap buffer")
    print(f"[*] arg2 (DX):  0x{arg2_val:04x}")
    
    # Enable tracing for initial instructions
    emu.trace_instructions = False  # Set True for full trace
    
    # Run emulation
    result = emu.emulate_function(arg1_ptr, arg2_val, max_instructions=50000)
    
    if result is not None:
        print("\n" + "=" * 70)
        print(f"[SUCCESS] Function returned: 0x{result:016x} ({result})")
        print("=" * 70)
    else:
        print("\n" + "=" * 70)
        print("[FAILED] Emulation did not complete successfully")
        print("=" * 70)
    
    print("\n[*] Tips for analyzing this obfuscated function:")
    print("    1. State machine dispatcher at 0x14008259E")
    print("    2. Multiple junk calls that just return RCX")
    print("    3. ICEBP/INT1 instruction at 0x14008264C (anti-debug)")
    print("    4. Heavy arithmetic obfuscation (MBA)")
    print("    5. Consider symbolic execution with angr")
    print("\n    Dispatcher states seen in code:")
    print("      0xA356BCC8, 0xB9369287, 0x1BE22863, 0x31AA5FDA,")
    print("      0x49BBE3FA, 0x4A0D7292, 0x54E95098, 0x66951443")

if __name__ == "__main__":
    main()