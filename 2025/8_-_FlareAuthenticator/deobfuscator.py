#!/usr/bin/env python3
import re
import sys

class ASMDeobfuscator:
    def __init__(self, asm_file):
        with open(asm_file, 'r', encoding='utf-8', errors='ignore') as f:
            self.asm_content = f.read()
        
        # Parse all offset definitions (e.g., off_1400C2960 dq 0E8DE54F1FA844D7Dh)
        self.offsets = {}
        self.parse_offsets()
        
        # Parse all functions and code blocks
        self.functions = {}
        self.code_blocks = {}
        self.parse_functions()
        
        # Statistics
        self.stats = {
            'junk_calls': 0,
            'interesting_calls': 0,
            'unable_to_find': 0,
            'total_calls': 0
        }
    
    def parse_offsets(self):
        """Parse all offset definitions from the ASM file"""
        pattern = r'^([0-9A-F]+)\s+(off_[0-9A-F]+)\s+dq\s+([0-9A-F]+)h'
        for line in self.asm_content.split('\n'):
            match = re.match(pattern, line.strip())
            if match:
                addr, name, value = match.groups()
                self.offsets[name] = int(value, 16)
    
    def parse_functions(self):
        """Parse all functions and their content"""
        lines = self.asm_content.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i].rstrip('\n')
            stripped = line.strip()
            # Match function start: sub_XXXXXXXX proc near
            func_match = re.match(r'^([0-9A-F]+)\s+(sub_[0-9A-F]+)\s+proc\s+near', stripped)
            if func_match:
                func_addr_str, func_name = func_match.groups()
                func_addr = int(func_addr_str, 16)
                
                # Find function end
                func_lines = [lines[i]]
                i += 1
                while i < len(lines):
                    func_lines.append(lines[i])
                    if re.search(rf'{func_name}\s+endp', lines[i]):
                        break
                    i += 1
                
                self.functions[func_name] = {
                    'addr': func_addr,
                    'lines': func_lines
                }
            
            # Also parse code blocks that might be jump targets (align blocks)
            elif re.match(r'^([0-9A-F]+)\s+', stripped):
                addr_match = re.match(r'^([0-9A-F]+)\s+(.+)', stripped)
                if addr_match:
                    addr_str, instr = addr_match.groups()
                    addr = int(addr_str, 16)
                    
                    # Store individual instructions by address
                    if addr not in self.code_blocks:
                        self.code_blocks[addr] = []
                    # Keep original instr (may contain comments/annotations after semicolon)
                    self.code_blocks[addr].append(instr.strip())
            
            i += 1
    
    def calculate_call_target(self, offset_name, constant):
        """Calculate the actual call target address"""
        if offset_name not in self.offsets:
            return None
        
        offset_value = self.offsets[offset_name]
        constant_value = int(constant, 16) if isinstance(constant, str) else constant
        
        # Handle negative values (two's complement for 64-bit)
        if constant_value >= 0x8000000000000000:
            constant_value = constant_value - 0x10000000000000000
        if offset_value >= 0x8000000000000000:
            offset_value = offset_value - 0x10000000000000000
        
        # Add them and keep as 64-bit address
        result = (offset_value + constant_value) & 0xFFFFFFFFFFFFFFFF
        
        return result
    
    def find_function_at_address(self, target_addr):
        """Find function or code block at the given address"""
        # First check if it's a function start
        for func_name, func_data in self.functions.items():
            if func_data['addr'] == target_addr:
                return func_name, func_data['lines']
        
        # Check if it's a code block (might be in middle of function)
        if target_addr in self.code_blocks:
            return f"0x{target_addr:016X}", self.code_blocks[target_addr]
        
        return None, None
    
    def is_junk_code(self, code_lines):
        """
        Determine if code is a junk function.

        Returns tuple: (is_junk: bool, instructions: list[str], annotation: str|None)

        - If an annotation/collapsed-function comment is found, treat as interesting (is_junk=False)
          and return the annotation string so it can be included in the comment.
        - Otherwise apply the previous heuristics to detect tiny junk wrappers.
        """
        if not code_lines:
            return False, [], None
        
        # First: look for collapsed-function or bracketed annotation comments like:
        #   ; [00000006 BYTES: COLLAPSED FUNCTION QString::~QString(void)]
        # or inline: "000000014008E0D0 ; [00000006 BYTES: COLLAPSED FUNCTION ...]"
        annotation = None
        collapsed_pattern = re.compile(r'\[.*?(COLLAPSED FUNCTION|BYTES:|FUNCTION).*?\]', re.IGNORECASE)
        for line in code_lines:
            # check the whole line for bracketed annotation
            m = collapsed_pattern.search(line)
            if m:
                # extract the bracketed text
                br = re.search(r'(\[.*?\])', line)
                if br:
                    annotation = br.group(1)
                else:
                    annotation = m.group(0)
                # treat this as *not* junk (it's interesting / informative)
                return False, [], annotation
        
        # Extract only instruction lines (ignore labels, proc, endp, comment-only lines)
        instructions = []
        for line in code_lines:
            # remove any trailing comment after ';' so we only inspect instruction itself
            inst_part = line.split(';', 1)[0].strip()
            # Match lines with actual instructions (same set as before)
            instr_match = re.search(r'(?:mov|add|sub|lea|xor|and|or|ret|retn|nop|call|push|pop|cmp|test|jmp)\s+.+', inst_part, re.IGNORECASE)
            if instr_match:
                # Clean up the instruction (remove leading addresses if present)
                instr = re.sub(r'^[0-9A-F]+\s+', '', inst_part).strip()
                instructions.append(instr)
        
        # Common junk patterns
        junk_patterns = [
            (r'mov\s+rax,\s*rcx', r'retn?'),  # mov rax, rcx; ret
            (r'mov\s+rax,\s*rcx', r'add\s+rax,\s*\w+', r'retn?'),  # mov rax, rcx; add rax, X; ret
            (r'lea\s+rax,\s*\[.*\]', r'retn?'),  # lea rax, [...]; ret
            (r'nop', r'retn?'),  # nop; ret
            (r'xor\s+eax,\s*eax', r'retn?'),  # xor eax, eax; ret
        ]
        
        # Check if instructions match junk patterns
        for pattern_set in junk_patterns:
            if len(instructions) == len(pattern_set):
                match = True
                for i, pattern in enumerate(pattern_set):
                    if not re.search(pattern, instructions[i], re.IGNORECASE):
                        match = False
                        break
                if match:
                    return True, instructions, None
        
        # If only 0-2 simple instructions, likely junk. However: if there are zero instructions
        # but we didn't find an annotation, be conservative and treat small n as junk.
        if len(instructions) <= 2:
            return True, instructions, None
        
        return False, instructions, None
    
    def deobfuscate_function(self, func_name):
        """Deobfuscate a specific function"""
        if func_name not in self.functions:
            print(f"Error: Function {func_name} not found!")
            return None
        
        func_data = self.functions[func_name]
        result_lines = []
        
        i = 0
        lines = func_data['lines']
        
        while i < len(lines):
            line = lines[i]
            result_lines.append(line)
            
            # Check for indirect call pattern
            if re.search(r'call\s+rax', line, re.IGNORECASE):
                self.stats['total_calls'] += 1
                
                # Look backwards to find the offset loading and constant
                offset_name = None
                constant = None
                
                # Search previous lines for mov rax, cs:off_XXXX and mov rdx/add pattern
                for j in range(i-1, max(i-50, -1), -1):  # widen search a bit for robustness
                    prev_line = lines[j]
                    
                    # Match: mov rax, cs:off_XXXXXXXX
                    offset_match = re.search(r'mov\s+rax,\s+cs:(off_[0-9A-F]+)', prev_line, re.IGNORECASE)
                    if offset_match:
                        offset_name = offset_match.group(1)
                    
                    # Match: mov rdx, CONSTANT or mov rcx, CONSTANT (handle common variants)
                    const_match = re.search(r'mov\s+(?:rdx|rcx|rax),\s+([0-9A-F]+)h', prev_line, re.IGNORECASE)
                    if const_match:
                        constant = const_match.group(1)
                    
                    # If we found both, calculate
                    if offset_name and constant:
                        target_addr = self.calculate_call_target(offset_name, constant)
                        if target_addr:
                            target_name, target_code = self.find_function_at_address(target_addr)
                            
                            if target_name:
                                is_junk, instructions, annotation = self.is_junk_code(target_code)
                                
                                if is_junk:
                                    # --- JUNK: keep the (small) instruction dump as before ---
                                    self.stats['junk_calls'] += 1
                                    instr_str = ' ; '.join(instructions) if instructions else 'unknown'
                                    comment = f"\t\t\t; Junk call -> {target_name}\t\t; {instr_str}"
                                else:
                                    # --- INTERESTING: DO NOT append full instruction dump ---
                                    self.stats['interesting_calls'] += 1
                                    if annotation:
                                        # If we have a bracketed annotation, prefer that
                                        comment = f"\t\t\t; Interesting call -> {target_name} \t; {annotation}"
                                    else:
                                        # Create a short summary: first instruction + ... (+N more)
                                        if instructions:
                                            first = instructions[0]
                                            more = len(instructions) - 1
                                            if more > 0:
                                                comment = f"\t\t\t; Interesting call -> {target_name} \t; {first} ... (+{more} more)"
                                            else:
                                                # single instruction only: include it but still short
                                                comment = f"\t\t\t; Interesting call -> {target_name} \t; {first}"
                                        else:
                                            # No instruction details: leave minimal comment
                                            comment = f"\t\t\t; Interesting call -> {target_name}"
                                
                                # Update the last line with comment
                                result_lines[-1] = result_lines[-1].rstrip() + comment
                            else:
                                self.stats['unable_to_find'] += 1
                                result_lines[-1] = result_lines[-1].rstrip() + f"\t\t\t; Unable to find target at 0x{target_addr:016X}"
                        break
            
            i += 1
        
        return '\n'.join(result_lines)
    
    def print_statistics(self):
        """Print analysis statistics"""
        print("\n" + "="*70)
        print("DEOBFUSCATION ANALYSIS SUMMARY")
        print("="*70)
        print(f"Total indirect calls analyzed:\t\t{self.stats['total_calls']}")
        print(f"  ├─ Junk calls:\t\t\t{self.stats['junk_calls']}")
        print(f"  ├─ Interesting calls:\t\t\t{self.stats['interesting_calls']}")
        print(f"  └─ Unable to find target:\t\t{self.stats['unable_to_find']}")
        print("="*70 + "\n")


def main():
    if len(sys.argv) != 3:
        print("Usage: python deobfuscator.py <asm_file> <function_name>")
        print("Example: python deobfuscator.py dump.asm sub_1400202B0")
        sys.exit(1)
    
    asm_file = sys.argv[1]
    func_name = sys.argv[2]
    
    try:
        deobf = ASMDeobfuscator(asm_file)
        result = deobf.deobfuscate_function(func_name)
        
        if result:
            # Save to file
            output_file = f"{func_name}_deobfuscated.asm"
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(result)
            
            # Print statistics only (not the code)
            deobf.print_statistics()
            print(f"[+] Deobfuscated function saved to {output_file}")
        
    except FileNotFoundError:
        print(f"Error: File '{asm_file}' not found!")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
