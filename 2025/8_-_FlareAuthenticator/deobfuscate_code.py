import re
import struct
import pefile

class AsmDeobfuscator:
    def __init__(self, binary_path, ida_data_file, base_address=0x140000000):
        self.binary_path = binary_path
        self.ida_data_file = ida_data_file
        self.base_address = base_address
        self.pe = None
        self.ida_data = {}
        self.imports = {}  # VA -> function name mapping
        self.load_binary()
        self.load_ida_data()
        self.load_imports()
    
    def load_binary(self):
        """Load the PE file"""
        try:
            self.pe = pefile.PE(self.binary_path)
            print(f"[+] Loaded PE file: {self.binary_path}")
            print(f"[+] Image Base: 0x{self.pe.OPTIONAL_HEADER.ImageBase:X}")
        except Exception as e:
            print(f"[-] Error loading PE file: {e}")
            self.pe = None
    
    def load_imports(self):
        """Load IAT entries and create VA to function name mapping"""
        if not self.pe:
            return
        
        try:
            if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                    for imp in entry.imports:
                        if imp.address and imp.name:
                            func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                            va = self.base_address + imp.address
                            self.imports[va] = f"{dll_name}!{func_name}"
                
                print(f"[+] Loaded {len(self.imports)} import symbols")
        except Exception as e:
            print(f"[-] Error loading imports: {e}")
    
    def load_ida_data(self):
        """Load IDA data dump and parse dq/db values"""
        try:
            with open(self.ida_data_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            print(f"[+] Parsing IDA data file: {self.ida_data_file}")
            
            for line in lines:
                # Match dq entries: .data:000000014009F4A8 off_14009F4A8   dq 0E69843EE12D93A74h
                dq_match = re.search(r'\.data:([0-9A-Fa-f]+)\s+.*?\s+dq\s+([0-9A-Fa-f]+)h', line)
                if dq_match:
                    addr = int(dq_match.group(1), 16)
                    value = int(dq_match.group(2), 16)
                    self.ida_data[addr] = value
                    continue
                
                # Match db entries: .data:000000014009F491                 db 0FFh ; ÿ
                db_match = re.search(r'\.data:([0-9A-Fa-f]+)\s+.*?\s+db\s+([0-9A-Fa-f]+)h', line)
                if db_match:
                    addr = int(db_match.group(1), 16)
                    byte_val = int(db_match.group(2), 16)
                    
                    # Store individual bytes, we'll reconstruct qwords later
                    if addr not in self.ida_data:
                        self.ida_data[addr] = byte_val
            
            print(f"[+] Loaded {len(self.ida_data)} data entries from IDA")
        except Exception as e:
            print(f"[-] Error loading IDA data: {e}")
    
    def read_qword_at_va(self, va):
        """Read a QWORD (8 bytes) from IDA data"""
        # Check if we have a direct dq entry
        if va in self.ida_data:
            value = self.ida_data[va]
            # If it's already a qword (> 0xFF), return it
            if value > 0xFF:
                return value
        
        # Otherwise, try to reconstruct from 8 consecutive bytes (little-endian)
        try:
            bytes_list = []
            for i in range(8):
                if (va + i) in self.ida_data:
                    bytes_list.append(self.ida_data[va + i] & 0xFF)
                else:
                    # If we can't get all 8 bytes, return None
                    return None
            
            # Pack as little-endian qword
            qword = struct.unpack('<Q', bytes(bytes_list))[0]
            return qword
        except:
            return None
    
    def va_to_file_offset(self, va):
        """Convert virtual address to file offset using PE parser"""
        if not self.pe:
            return None
        
        try:
            rva = va - self.base_address
            file_offset = self.pe.get_offset_from_rva(rva)
            return file_offset
        except:
            return None
    
    def check_if_junk_function(self, resolved_addr):
        """Check if the resolved address points to a junk function"""
        if not self.pe:
            return False
        if resolved_addr == 0x1400809e0:
            print(self.va_to_file_offset(resolved_addr))
        try:
            file_offset = self.va_to_file_offset(resolved_addr)
            if file_offset is None:
                return False
            
            # Read first 16 bytes to check patterns
            data = self.pe.get_data(file_offset, 16)
            if len(data) < 4:
                return False
            
            # Pattern 1: mov rax, rcx; retn = 48 89 C8 C3
            if data[:4] == b'\x48\x89\xC8\xC3':
                return True
            
            # Pattern 2: mov rax, rcx; ret = 48 89 C1 C3 (alternative encoding)
            if data[:4] == b'\x48\x89\xC1\xC3':
                return True
            
            # Pattern 3: mov rax, rcx; add rax, <imm8>; ret
            # 48 89 C8 = mov rax, rcx
            # 48 83 C0 XX = add rax, imm8
            # C3 = ret
            if len(data) >= 7:
                if data[:3] == b'\x48\x89\xC8' and data[3:6] == b'\x48\x83\xC0' and data[7] == 0xC3:
                    return True

            if data[:3] == b'\x48\x89\xC8' and data[3:6] == b'\x48\x83\xC0' and data[7] == 0x08 and data[8] == 0xC3:
                return True
            # Pattern 4: mov rax, rcx; add rax, <imm32>; ret
            # 48 89 C8 = mov rax, rcx
            # 48 05 XX XX XX XX = add rax, imm32
            # C3 = ret
            if len(data) >= 9:
                if data[:3] == b'\x48\x89\xC8' and data[3:5] == b'\x48\x05' and data[9] == 0xC3:
                    return True
            
            # Pattern 5: Just add rax, imm8; ret (without mov)
            # 48 83 C0 XX = add rax, imm8
            # C3 = ret
            if len(data) >= 5:
                if data[:3] == b'\x48\x83\xC0' and data[4] == 0xC3:
                    return True
        except:
            pass
        
        return False
    
    def parse_asm_file(self, asm_file_path):
        """Parse assembly file and deobfuscate call rax patterns"""
        try:
            with open(asm_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except Exception as e:
            print(f"[-] Error reading assembly file: {e}")
            return None
        
        output_lines = []
        processed_count = 0
        junk_count = 0
        valid_count = 0
        
        i = 0
        while i < len(lines):
            line = lines[i]
            
            # Check if this is a "call rax" instruction
            if re.search(r'\bcall\s+rax\b', line, re.IGNORECASE):
                # Look back for the pattern
                result = self.analyze_call_pattern(lines, i)
                if result:
                    processed_count += 1
                    is_junk, comment = result
                    if is_junk:
                        junk_count += 1
                    else:
                        valid_count += 1
                    # Add comment to the line
                    output_lines.append(line.rstrip() + f"  ; {comment}\n")
                else:
                    output_lines.append(line)
            else:
                output_lines.append(line)
            
            i += 1
        
        print(f"[+] Processed {processed_count} call rax instructions")
        print(f"    - Valid calls: {valid_count}")
        print(f"    - Junk calls: {junk_count}")
        
        return output_lines
    
    def analyze_call_pattern(self, lines, call_line_idx):
        """Analyze the pattern before call rax to determine the target"""
        mov_rax_line = None
        add_value = None
        offset_va = None
        
        # Look back up to 15 lines
        for j in range(max(0, call_line_idx - 15), call_line_idx):
            line = lines[j]
            
            # Match: mov rax, cs:off_XXXXX or mov rax, cs:qword_XXXXX
            mov_match = re.search(r'mov\s+rax,\s+cs:(\w+)', line, re.IGNORECASE)
            if mov_match:
                offset_match = re.search(r'(?:off|qword|unk)_([0-9A-Fa-f]+)', line)
                if offset_match:
                    offset_va = int(offset_match.group(1), 16)
                    mov_rax_line = j
            
            # Match: mov rcx/rdx, IMMEDIATE
            if mov_rax_line is not None:
                add_match = re.search(r'mov\s+(rcx|rdx),\s+([0-9A-Fa-f]+)h', line, re.IGNORECASE)
                if add_match:
                    add_value = int(add_match.group(2), 16)
                
                # Check for direct add
                add_direct = re.search(r'add\s+rax,\s+(rcx|rdx)', line, re.IGNORECASE)
                if add_direct and add_value is not None:
                    break
        
        if offset_va is None or add_value is None:
            return None
        
        # Read the QWORD from IDA data
        stored_value = self.read_qword_at_va(offset_va)
        if stored_value is None:
            return (False, f"Cannot read value at VA 0x{offset_va:X}")
        
        # Calculate final address and mask to 64-bit
        resolved_addr = (stored_value + add_value) & 0xFFFFFFFFFFFFFFFF
        
        # Check if it's an import symbol
        print(f"Resolved addr:    {hex(resolved_addr)}")
        symbol_name = self.imports.get(resolved_addr)
        
        # Check if it's a junk function
        is_junk = self.check_if_junk_function(resolved_addr)
        
        if is_junk:
            comment = f"JUNK (0x{stored_value:X} + 0x{add_value:X} = 0x{resolved_addr:X})"
            return (True, comment)
        elif symbol_name:
            comment = f"0x{stored_value:X} + 0x{add_value:X} = 0x{resolved_addr:X} -> {symbol_name}"
            return (False, comment)
        else:
            comment = f"0x{stored_value:X} + 0x{add_value:X} = 0x{resolved_addr:X}"
            return (False, comment)
    
    def deobfuscate(self, asm_file_path, output_file_path):
        """Main deobfuscation function"""
        if not self.pe:
            print("[-] PE file not loaded. Cannot continue.")
            return
        
        if not self.ida_data:
            print("[-] IDA data not loaded. Cannot continue.")
            return
        
        print(f"[+] Parsing assembly file: {asm_file_path}")
        output_lines = self.parse_asm_file(asm_file_path)
        
        if output_lines:
            with open(output_file_path, 'w', encoding='utf-8') as f:
                f.writelines(output_lines)
            print(f"[+] Deobfuscated assembly written to: {output_file_path}")
        else:
            print("[-] Failed to parse assembly file")


# Usage example
if __name__ == "__main__":
    # Configure paths
    BINARY_PATH = "FlareAuthenticator.exe"
    IDA_DATA_FILE = "data_values.txt"  # Your IDA .data section dump
    ASM_INPUT = "obfuscated_2b20.asm"
    ASM_OUTPUT = "deobfuscated_function.asm"
    
    # Create deobfuscator instance
    deobfuscator = AsmDeobfuscator(
        binary_path=BINARY_PATH,
        ida_data_file=IDA_DATA_FILE,
        base_address=0x140000000
    )
    
    # Run deobfuscation
    deobfuscator.deobfuscate(ASM_INPUT, ASM_OUTPUT)