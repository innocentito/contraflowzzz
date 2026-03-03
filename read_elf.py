import sys
from elftools.elf.elffile import ELFFile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

"""  der nächste Schritt Stack-String-Detektion oder automatisches Entschlüsseln erkannter
  XOR-Keys  """

def get_jump_target(insn):
    if insn.operands and insn.operands[0].type == 2:
        return insn.operands[0].imm
    try:
        return int(insn.op_str, 16)
    except ValueError:
        return None

def find_loops(instructions):
    """Returns list of (start_idx, end_idx, jump_insn) for each detected loop."""
    addr_to_idx = {insn.address: i for i, insn in enumerate(instructions)}
    loops = []
    for insn in instructions:
        if is_backward_jump(insn):
            target = get_jump_target(insn)
            if target is not None and target in addr_to_idx:
                loops.append((addr_to_idx[target], addr_to_idx[insn.address], insn))
    return loops

def detect_xor_loops(instructions):
    findings = []
    for start_idx, end_idx, jump in find_loops(instructions):
        for insn in instructions[start_idx:end_idx + 1]:
            if insn.mnemonic == 'xor' and not is_setup_xor(insn):
                findings.append({'xor': insn, 'jump': jump})
    return findings

def detect_rol_ror_loops(instructions):
    findings = []
    for start_idx, end_idx, jump in find_loops(instructions):
        for insn in instructions[start_idx:end_idx + 1]:
            if insn.mnemonic in ('rol', 'ror'):
                findings.append({'rotate': insn, 'jump': jump})
    return findings

def is_backward_jump(insn):
    if insn.mnemonic.startswith('j') or insn.mnemonic.startswith('loop'):
        if insn.operands and len(insn.operands) > 0:
            if insn.operands[0].type == 2:  # Immediate
                target = insn.operands[0].imm
                return target < insn.address
        try: 
            target = int(insn.op_str, 16)
            return target < insn.address
        except ValueError:
            return False
    return False

def is_setup_xor(insn):
    ops = insn.op_str.split(', ')
    if len(ops) == 2:
        return ops[0].strip() == ops[1].strip()
    return False
    
def detect_xor_constants(instructions):
    findings = []
    for insn in instructions:
        if insn.mnemonic == 'xor' and not is_setup_xor(insn):
            if insn.operands and len(insn.operands) > 1:
                if insn.operands[1].type == 2:
                    imm = insn.operands[1].imm
                    if imm > 0xFF:
                        findings.append(insn)
    return findings

def load_instructions(filename):
    f = open(filename, 'rb')  # File bleibt offen!
    elf = ELFFile(f)
    all_instructions = []

    for section in elf.iter_sections():
        if section['sh_flags'] & 0x4:  # SHF_EXECINSTR
            data = section.data()
            if len (data) > 0:

                is_64bit = elf.elfclass == 64
                mode = CS_MODE_64 if is_64bit else CS_MODE_32
                md = Cs(CS_ARCH_X86, mode)
                md.detail = True
                base_addr = section['sh_addr']
                instructions = list(md.disasm(data, base_addr))
                all_instructions.extend(instructions)
    if all_instructions:
        return elf, all_instructions, f

    return None, None, None


def show_sections(elf):
    print("Sections in binary:")
    for section in elf.iter_sections():
        print(f"  {section.name}")
            
def disassemble(instructions):
    # Disassemble
    for instruction in instructions:
        print(f"0x{instruction.address:x}: {instruction.mnemonic} {instruction.op_str}")

def show_all_xors(instructions):
    # Alle XORs
    all_xors = [insn for insn in instructions if insn.mnemonic == 'xor']
    print(f"Total XOR instructions found: {len(all_xors)}")
    for xor in all_xors:
        print(f"  0x{xor.address:x}: {xor.mnemonic} {xor.op_str}")

def analyze_rotate_loops(instructions):
    
    rotate_loops = detect_rol_ror_loops(instructions)
    print(f"ROL/ROR Loops detected: {len(rotate_loops)}")
    print()

    if rotate_loops:
        print("\nSuspicious ROL/ROR Loops:")
        for loop in rotate_loops:
            print(f"     Rotate at 0x{loop['rotate'].address:x}: {loop['rotate'].mnemonic} {loop['rotate'].op_str}")
            print(f"     Loop at 0x{loop['jump'].address:x}: {loop['jump'].mnemonic} {loop['jump'].op_str}")
            print()

def analyze_xor_loops(instructions):
    # Nur Loops
    xor_loops = detect_xor_loops(instructions)
    print(f"XOR Loops detected: {len(xor_loops)}")
    print()

    if xor_loops:
        print("\nSuspicious XOR Loops:")
        for loop in xor_loops:
            print(f"     XOR at 0x{loop['xor'].address:x}: {loop['xor'].mnemonic} {loop['xor'].op_str}")
            print(f"     Loop at 0x{loop['jump'].address:x}: {loop['jump'].mnemonic} {loop['jump'].op_str}")
            print()

def analyze_xor_constants(instructions):
    # Nur Konstanten
    xor_constants = detect_xor_constants(instructions)
    print(f"XOR with magic constants detected: {len(xor_constants)}")

    if xor_constants:
        print("\nSuspicious XOR with Constants:")
        for xor in xor_constants:
            print(f"     XOR at 0x{xor.address:x}: {xor.mnemonic} {xor.op_str} (constant: {xor.operands[1].imm:x})")


def show_menu():
    print("\nWhat do you want to analyze?")
    print("[1] Show sections")
    print("[2] Disassemble")
    print("[3] Show all XORs")
    print("[4] Analyze XOR loops")
    print("[5] Analyze XOR constants")
    print("[6] Analyze ROL/ROR loops")
    print("[0] Exit")
    print()
    choice = input(">> choose: ").strip()
    print()
    return choice

filename = input("Enter binary path: ")

try:
    elf, instructions, f = load_instructions(filename)
except FileNotFoundError:
    print(f"Error: Binary '{filename}' not found")
    sys.exit(1)
except Exception as e:
    print(f"Error loading binary: {e}")
    sys.exit(1)

if instructions is None:
    print("Error: .text section not found in binary")
    sys.exit(1)

# Main menu loop
while True:
    choice = show_menu()

    if choice == '1':
        show_sections(elf)
    elif choice == '2':
        disassemble(instructions)
    elif choice == '3':
        show_all_xors(instructions)
    elif choice == '4':
        analyze_xor_loops(instructions)
    elif choice == '5':
        analyze_xor_constants(instructions)
    elif choice == '6':
        analyze_rotate_loops(instructions)
    elif choice == '0':
        print("Exiting...")
        f.close()
        break
    else:
        print("Invalid choice!")