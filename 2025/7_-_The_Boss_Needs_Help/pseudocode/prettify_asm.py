#!/usr/bin/env python3
import re
import sys
from collections import deque

# --- Configuration ---
# You can change the number of context lines to show before and after a match.
CONTEXT_LINES = 4

def filter_disassembly_with_context(disassembly_lines, compiled_regex_pattern, register_list):
    """
    Filters disassembly lines, showing matching lines with surrounding context.

    Args:
        disassembly_lines (iterable): An iterable of strings (e.g., a list or file handle).
        compiled_regex_pattern (re.Pattern): The compiled regex pattern to search with.
        register_list (list): The list of registers for the final report.
    """
    found_match = False
    # A deque with a fixed max length is perfect for holding the "before" context.
    # It automatically discards the oldest item when a new one is added.
    before_buffer = deque(maxlen=CONTEXT_LINES)
    after_countdown = 0

    for line in disassembly_lines:
        line_stripped = line.strip()
        
        if compiled_regex_pattern.search(line_stripped):
            # This is a new match, not part of the 'after' context of a previous match
            if after_countdown == 0 and found_match:
                print("---") # Separator for distinct blocks of matches

            # Print the "before" context from the buffer
            while before_buffer:
                print(f"  {before_buffer.popleft()}")

            # Print the actual matching line, marked with a '>'
            print(f"> {line_stripped}")
            
            found_match = True
            # Start the countdown to print the next N lines of "after" context
            after_countdown = CONTEXT_LINES
        
        elif after_countdown > 0:
            # We are in "after" context mode, so print this line
            print(f"  {line_stripped}")
            after_countdown -= 1
        else:
            # Not a match and not in "after" context, just add to the "before" buffer
            before_buffer.append(line_stripped)
    
    if not found_match:
        print(f"\nNo lines found containing any of the specified registers: {', '.join(register_list)}")


def main():
    """Main function to run the script."""
    if len(sys.argv) > 2:
        print("Usage: python filter_script.py [filename]")
        print("If no filename is provided, it will wait for piped input.")
        sys.exit(1)

    # The script now uses this hardcoded list of registers
    # decrypt_post_main_target_registers = ["rsi", "rdi", "r14"]
    target_registers= ["rsi", "r12"]

    if not target_registers:
        print("Error: No register names are specified in the script.")
        return

    print(f"\n--- Filtering for registers: {', '.join(target_registers)} (with {CONTEXT_LINES} lines of context) ---\n")

    # Build the regex pattern to match any of the registers
    try:
        escaped_registers = [re.escape(reg) for reg in target_registers]
        pattern_str = r"\b(" + "|".join(escaped_registers) + r")\b"
        compiled_pattern = re.compile(pattern_str, re.IGNORECASE)
    except re.error as e:
        print(f"Error: Invalid register name for regex. {e}")
        return

    if len(sys.argv) == 2:
        # A filename was provided
        try:
            with open(sys.argv[1], 'r') as f:
                filter_disassembly_with_context(f, compiled_pattern, target_registers)
        except FileNotFoundError:
            print(f"Error: File not found at '{sys.argv[1]}'")
    else:
        # No filename, read from standard input
        print("Waiting for input. Paste your disassembly and press Ctrl+D (Linux/macOS) or Ctrl+Z then Enter (Windows) to finish.")
        filter_disassembly_with_context(sys.stdin, compiled_pattern, target_registers)


if __name__ == "__main__":
    main()