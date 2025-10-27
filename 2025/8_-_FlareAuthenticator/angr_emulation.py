#!/usr/bin/env python3
"""
Angr Symbolic Execution for sub_140081760
Handles unknown heap data via symbolic execution
Extracts the ACTUAL algorithm without needing concrete values
"""

import angr
import claripy
import sys

def setup_symbolic_execution(binary_path):
    """
    Setup angr project with symbolic arguments
    This way we don't need actual heap data!
    """
    print("[*] Loading binary with angr...")
    
    # Load binary (don't load system libraries)
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    print(f"[+] Binary loaded: {proj.filename}")
    print(f"    Architecture: {proj.arch}")
    print(f"    Base address: 0x{proj.loader.main_object.mapped_base:x}")
    
    return proj

def create_symbolic_state(proj, function_addr=0x140081760):
    """
    Create state with symbolic arguments
    """
    print(f"\n[*] Creating symbolic state at 0x{function_addr:x}")
    
    # Create symbolic variables
    # RCX - pointer to structure (we make the STRUCTURE symbolic)
    rcx_ptr = 0x200000000  # Concrete address
    
    # DX - 16-bit shift key (symbolic)
    dx_symbolic = claripy.BVS('dx', 16)
    
    # Structure fields (all symbolic!)
    field_10_sym = claripy.BVS('field_10', 32)
    field_20_sym = claripy.BVS('field_20', 64)
    
    # Create call state
    state = proj.factory.call_state(
        function_addr,
        rcx_ptr,  # arg1 (concrete pointer)
        dx_symbolic,  # arg2 (symbolic)
        add_options={
            angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
            angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS
        }
    )
    
    # Initialize symbolic structure in memory
    state.memory.store(rcx_ptr + 0x10, field_10_sym, endness='Iend_LE')
    state.memory.store(rcx_ptr + 0x20, field_20_sym, endness='Iend_LE')
    
    print(f"[+] Structure at: 0x{rcx_ptr:x}")
    print(f"    field_10 (symbolic): {field_10_sym}")
    print(f"    field_20 (symbolic): {field_20_sym}")
    print(f"    dx (symbolic): {dx_symbolic}")
    
    return state, {'dx': dx_symbolic, 'field_10': field_10_sym, 'field_20': field_20_sym}

def explore_function(proj, state, max_steps=1000):
    """
    Explore the function symbolically
    """
    print(f"\n[*] Starting symbolic exploration (max {max_steps} steps)...")
    
    # Create simulation manager
    simgr = proj.factory.simulation_manager(state)
    
    # Explore until we hit return or deadend
    try:
        simgr.run(n=max_steps)
    except Exception as e:
        print(f"[!] Exploration stopped: {e}")
    
    print(f"\n[+] Exploration results:")
    print(f"    Active states: {len(simgr.active)}")
    print(f"    Deadended: {len(simgr.deadended)}")
    print(f"    Errored: {len(simgr.errored)}")
    
    return simgr

def extract_formulas(simgr, symbolic_vars, struct_addr=0x200000000):
    """
    Extract symbolic formulas showing what the function does
    """
    print(f"\n[*] Extracting symbolic formulas...")
    
    formulas = []
    
    for i, state in enumerate(simgr.deadended[:5]):  # Check first 5 results
        print(f"\n--- State {i} ---")
        
        try:
            # Get return value (RAX)
            rax = state.regs.rax
            
            # Get modified structure fields
            field_10_out = state.memory.load(struct_addr + 0x10, 4, endness='Iend_LE')
            field_20_out = state.memory.load(struct_addr + 0x20, 8, endness='Iend_LE')
            
            print(f"[+] Return value (RAX):")
            print(f"    Symbolic: {rax}")
            print(f"    Depth: {rax.depth}")
            
            print(f"\n[+] Modified field_10:")
            print(f"    Symbolic: {field_10_out}")
            
            print(f"\n[+] Modified field_20:")
            print(f"    Symbolic: {field_20_out}")
            
            # Try to simplify expressions
            print(f"\n[*] Attempting to simplify...")
            rax_simplified = state.solver.simplify(rax)
            print(f"    RAX (simplified): {rax_simplified}")
            
            # Check for specific patterns
            # Does it contain our input DX?
            if symbolic_vars['dx'] in rax.variables:
                print(f"    ✓ Return value depends on DX!")
            
            if symbolic_vars['field_20'] in field_20_out.variables:
                print(f"    ✓ field_20 is modified (PRNG update)!")
            
            formulas.append({
                'rax': rax,
                'field_10': field_10_out,
                'field_20': field_20_out
            })
            
        except Exception as e:
            print(f"[!] Error extracting formula: {e}")
    
    return formulas

def test_with_concrete_values(proj, dx_value, field_10_value, field_20_value):
    """
    Test with concrete values to verify our understanding
    """
    print(f"\n[*] Testing with concrete values:")
    print(f"    dx = 0x{dx_value:04x}")
    print(f"    field_10 = 0x{field_10_value:08x}")
    print(f"    field_20 = 0x{field_20_value:016x}")
    
    rcx_ptr = 0x200000000
    
    # Create concrete state
    state = proj.factory.call_state(
        0x140081760,
        rcx_ptr,
        dx_value
    )
    
    # Initialize with concrete values
    state.memory.store(rcx_ptr + 0x10, claripy.BVV(field_10_value, 32), endness='Iend_LE')
    state.memory.store(rcx_ptr + 0x20, claripy.BVV(field_20_value, 64), endness='Iend_LE')
    
    # Run
    simgr = proj.factory.simulation_manager(state)
    simgr.run(n=1000)
    
    if simgr.deadended:
        final_state = simgr.deadended[0]
        rax = final_state.solver.eval(final_state.regs.rax)
        field_10_out = final_state.solver.eval(
            final_state.memory.load(rcx_ptr + 0x10, 4, endness='Iend_LE')
        )
        field_20_out = final_state.solver.eval(
            final_state.memory.load(rcx_ptr + 0x20, 8, endness='Iend_LE')
        )
        
        print(f"\n[+] Results:")
        print(f"    RAX = 0x{rax:016x}")
        print(f"    field_10 = 0x{field_10_out:08x}")
        print(f"    field_20 = 0x{field_20_out:016x}")
        
        # Check PRNG pattern
        expected_prng = (field_20_value * 0x341B2E4D) % 0x3B305E4C
        if field_20_out == expected_prng:
            print(f"    ✓ PRNG matches expected LCG!")
        
        return rax, field_10_out, field_20_out
    else:
        print(f"[-] No successful execution")
        return None

def find_constraints(simgr, symbolic_vars):
    """
    Find what constraints exist on the symbolic variables
    """
    print(f"\n[*] Analyzing constraints...")
    
    for i, state in enumerate(simgr.deadended[:3]):
        print(f"\n--- State {i} Constraints ---")
        
        # Get all constraints
        constraints = state.solver.constraints
        print(f"Total constraints: {len(constraints)}")
        
        # Check for interesting constraints on our variables
        for var_name, var_sym in symbolic_vars.items():
            # Try to get bounds
            if state.solver.satisfiable():
                min_val = state.solver.min(var_sym)
                max_val = state.solver.max(var_sym)
                print(f"  {var_name}: [{min_val}, {max_val}]")

def main():
    if len(sys.argv) < 2:
        print("Usage: python angr_symbolic.py <binary.exe>")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    
    print("="*70)
    print("Angr Symbolic Execution for Obfuscated Function")
    print("No concrete heap data needed!")
    print("="*70)
    
    # Setup
    proj = setup_symbolic_execution(binary_path)
    state, symbolic_vars = create_symbolic_state(proj)
    
    # Explore symbolically
    simgr = explore_function(proj, state, max_steps=1000)
    
    # Extract formulas
    formulas = extract_formulas(simgr, symbolic_vars)
    
    # Find constraints
    find_constraints(simgr, symbolic_vars)
    
    # Test with concrete values
    print("\n" + "="*70)
    print("Testing with concrete values")
    print("="*70)
    
    test_with_concrete_values(
        proj,
        dx_value=0x1935,
        field_10_value=0xAABBCCDD,
        field_20_value=0x12345678
    )
    
    print("\n[*] Alternative approach: Hook junk functions")
    print("    Since most calls are just 'mov rax, rcx'")
    print("    We can hook them to speed up analysis:")
    print()
    print("    proj.hook(0x14001E740, angr.SIM_PROCEDURES['stubs']['ReturnUnconstrained']()")
    
    print("\n[*] For PwnFuzz blog:")
    print("    1. Show symbolic execution avoids needing heap data")
    print("    2. Compare angr output with manual analysis")
    print("    3. Demonstrate formula extraction")
    print("    4. Show how to validate with concrete tests")

if __name__ == "__main__":
    main()