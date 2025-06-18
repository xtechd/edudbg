import ctypes
import lief
import pefile
import re
import threading
import time
import tkinter as tk

from capstone import *
from capstone.x86 import *
from ctypes import wintypes
from tkinter import filedialog, messagebox

""" 
NOTE :
il faut utilisé cette commande de compile pour pouvoir avoir les symbole de l'adresse de debut du main pour break dessu direct.
x86_64-w64-mingw32-gcc -g -O0 main.c -o main.exe
"""

# Constants
CREATE_NEW_CONSOLE = 0x00000010
CREATE_SUSPENDED = 0x00000004
DEBUG_PROCESS = 0x00000001
DBG_CONTINUE = 0x00010002
EXCEPTION_DEBUG_EVENT = 1
EXIT_PROCESS_DEBUG_EVENT = 5
EXCEPTION_SINGLE_STEP = 0x80000004

PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
PROCESS_ALL_ACCESS = 0x1F0FFF
LIST_MODULES_ALL = 0x03

CONTEXT_AMD64 = 0x100000
CONTEXT_CONTROL = 0x1
CONTEXT_INTEGER = 0x3
CONTEXT_DEBUG_REGISTERS = 0x10

CONTEXT_CUSTOM = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS
CONTEXT_ALL = 0x0010003F

# Windows types
LPVOID = ctypes.c_void_p
DWORD = ctypes.c_uint32
ULONG_PTR = ctypes.c_ulonglong
HANDLE = LPVOID

# Windows structures
class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ExitStatus", ctypes.c_void_p),
        ("PebBaseAddress", ctypes.c_uint64),
        ("AffinityMask", ctypes.c_void_p),
        ("BasePriority", ctypes.c_void_p),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
    ]

class PEB(ctypes.Structure):
    _fields_ = [
        ("InheritedAddressSpace", ctypes.c_byte),
        ("ReadImageFileExecOptions", ctypes.c_byte),
        ("BeingDebugged", ctypes.c_byte),
        ("BitField", ctypes.c_byte),
        ("ImageUsesLargePages", ctypes.c_byte),
        ("SpareBits", ctypes.c_byte),
        ("Mutant", ctypes.c_void_p),
        ("ImageBaseAddress", ctypes.c_void_p),
        ("Ldr", ctypes.c_void_p),
        ("ProcessParameters", ctypes.c_void_p),
        ("SubSystemData", ctypes.c_void_p),
        ("ProcessHeap", ctypes.c_void_p),
        ("FastPebLock", ctypes.c_void_p),
        ("AtlThunkSListPtr", ctypes.c_void_p),
        ("IFEOKey", ctypes.c_void_p),
        ("CrossProcessFlags", ctypes.c_uint32),
        ("ProcessInJob", ctypes.c_byte),
        ("ProcessInitializing", ctypes.c_byte),
        ("ReservedBytes", ctypes.c_byte * 2),
        ("KernelCallbackTable", ctypes.c_void_p),
        ("UserSharedInfoPtr", ctypes.c_void_p),
        ("SystemReserved", ctypes.c_uint32 * 1),
        ("AtlThunkSListPtr32", ctypes.c_uint32),
        ("ApiSetMap", ctypes.c_void_p),
    ]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [
        ("cb", DWORD),
        ("lpReserved", LPVOID),
        ("lpDesktop", LPVOID),
        ("lpTitle", LPVOID),
        ("dwX", DWORD),
        ("dwY", DWORD),
        ("dwXSize", DWORD),
        ("dwYSize", DWORD),
        ("dwXCountChars", DWORD),
        ("dwYCountChars", DWORD),
        ("dwFillAttribute", DWORD),
        ("dwFlags", DWORD),
        ("wShowWindow", ctypes.c_ushort),
        ("cbReserved2", ctypes.c_ushort),
        ("lpReserved2", LPVOID),
        ("hStdInput", HANDLE),
        ("hStdOutput", HANDLE),
        ("hStdError", HANDLE),
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", HANDLE),
        ("hThread", HANDLE),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
    ]

class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [
        ("dwDebugEventCode", DWORD),
        ("dwProcessId", DWORD),
        ("dwThreadId", DWORD),
        ("u", ctypes.c_byte * 1600),
    ]

class CONTEXT64(ctypes.Structure):
    _fields_ = [
        ("P1Home", ULONG_PTR),
        ("P2Home", ULONG_PTR),
        ("P3Home", ULONG_PTR),
        ("P4Home", ULONG_PTR),
        ("P5Home", ULONG_PTR),
        ("P6Home", ULONG_PTR),
        ("ContextFlags", DWORD),
        ("MxCsr", DWORD),
        ("SegCs", wintypes.WORD),
        ("SegDs", wintypes.WORD),
        ("SegEs", wintypes.WORD),
        ("SegFs", wintypes.WORD),
        ("SegGs", wintypes.WORD),
        ("SegSs", wintypes.WORD),
        ("EFlags", DWORD),
        ("Dr0", ULONG_PTR),
        ("Dr1", ULONG_PTR),
        ("Dr2", ULONG_PTR),
        ("Dr3", ULONG_PTR),
        ("Dr6", ULONG_PTR),
        ("Dr7", ULONG_PTR),
        ("Rax", ULONG_PTR),
        ("Rcx", ULONG_PTR),
        ("Rdx", ULONG_PTR),
        ("Rbx", ULONG_PTR),
        ("Rsp", ULONG_PTR),
        ("Rbp", ULONG_PTR),
        ("Rsi", ULONG_PTR),
        ("Rdi", ULONG_PTR),
        ("R8", ULONG_PTR),
        ("R9", ULONG_PTR),
        ("R10", ULONG_PTR),
        ("R11", ULONG_PTR),
        ("R12", ULONG_PTR),
        ("R13", ULONG_PTR),
        ("R14", ULONG_PTR),
        ("R15", ULONG_PTR),
        ("Rip", ULONG_PTR),
        ("DebugControl", ULONG_PTR),
        ("LastBranchToRip", ULONG_PTR),
        ("LastBranchFromRip", ULONG_PTR),
        ("LastExceptionToRip", ULONG_PTR),
        ("LastExceptionFromRip", ULONG_PTR),
    ]

# Load Windows DLLs
kernel32 = ctypes.windll.kernel32
psapi = ctypes.WinDLL('psapi')
ntdll = ctypes.WinDLL('ntdll.dll')

# Set function prototypes
ntdll.NtQueryInformationProcess.argtypes = [
    HANDLE,
    ctypes.c_uint32,
    LPVOID,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]

# Global variables
current_file = None
process_info = None
is_running = False
is_paused = False
current_context = None
current_thread_handle = None
backup_Dr = [0, 0, 0, 0]
backup_Dr7 = 0
continue_event = None
breakpoints = {}
main_addr = 0

# GUI widgets
root = None
debug_console = None
registers_view = None
stack_view = None
memory_view = None
breakpoint_list = None
bp_input = None
hx_input = None
hex_view = None
function_view = None
addr_str = None
button_pressed = None
button_lock = threading.Lock()
selected_label = None

def on_step_button():
    """Detect step button"""
    global button_pressed
    with button_lock:
        button_pressed = "step"
    return True

def on_step_over_button():
    """Detect step over button"""
    global button_pressed
    with button_lock:
        button_pressed = "step_over"
    return True

def on_continue_button():
    """Detect continue button"""
    global button_pressed
    with button_lock:
        button_pressed = "continue"
    return True

def on_stop_button():
    """Detect stop button"""
    global button_pressed
    with button_lock:
        button_pressed = "stop"
    return True

def on_break_button():
    """Detect stop button"""
    global button_pressed
    with button_lock:
        button_pressed = "add_breakpoint"
    return True

def on_search_hex_button():
    """Detect stop button"""
    global button_pressed
    with button_lock:
        button_pressed = "search_hex"
    return True

def check_button_pressed():
    """Check if any button was pressed"""
    global button_pressed
    with button_lock:
        if button_pressed:
            pressed = button_pressed
            button_pressed = None
            return pressed
    return None

def step_over():
    """Step over - execute next instruction, but step over function calls"""
    global current_context, current_thread_handle, process_info

    if not current_context or not current_thread_handle or not process_info:
        return False

    # Lire l'instruction courante pour détecter si c'est un CALL
    buffer = ctypes.create_string_buffer(16)  # Assez pour la plupart des instructions
    bytes_read = ctypes.c_size_t(0)

    if not kernel32.ReadProcessMemory(process_info.hProcess, ctypes.c_void_p(current_context.Rip), 
                                    buffer, 16, ctypes.byref(bytes_read)):
        append_to_console("[!] Failed to read memory for step over")
        return False

    # Désassembler l'instruction courante
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    instructions = list(md.disasm(buffer.raw[:bytes_read.value], current_context.Rip, count=1))

    if not instructions:
        append_to_console("[!] Failed to disassemble current instruction")
        return False

    current_instr = instructions[0]
    next_rip = current_instr.address + current_instr.size

    # Si c'est un CALL, on place un breakpoint temporaire après l'instruction
    if current_instr.mnemonic == "call":
        # Trouver un registre Dr libre pour le breakpoint temporaire
        context = CONTEXT64()
        context.ContextFlags = CONTEXT_CUSTOM
        
        if not kernel32.GetThreadContext(current_thread_handle, ctypes.byref(context)):
            append_to_console("[!] Failed to get thread context for step over")
            return False
        
        # Chercher un Dr libre
        free_dr = -1
        for i in range(4):
            if getattr(context, f"Dr{i}") == 0:
                free_dr = i
                break
        
        if free_dr == -1:
            append_to_console("[!] No free hardware breakpoint for step over - using single step instead")
            # Fallback sur step normal
            context.EFlags |= 0x100  # Trap flag
            if kernel32.SetThreadContext(current_thread_handle, ctypes.byref(context)):
                return True
            return False
        
        # Placer le breakpoint temporaire à l'instruction suivante
        setattr(context, f"Dr{free_dr}", next_rip)
        local_enable_bit = free_dr * 2
        context.Dr7 |= (1 << local_enable_bit)
        
        # Marquer ce breakpoint comme temporaire dans un dict global
        if 'temp_breakpoints' not in globals():
            global temp_breakpoints
            temp_breakpoints = {}
        temp_breakpoints[next_rip] = free_dr
        
        if kernel32.SetThreadContext(current_thread_handle, ctypes.byref(context)):
            append_to_console(f"[DEBUG] Step over: temporary breakpoint set at {next_rip:#018x}")
            return True
        else:
            append_to_console("[!] Failed to set temporary breakpoint for step over")
            return False

    else:
        # Pour toute autre instruction, faire un step normal
        context = CONTEXT64()
        context.ContextFlags = CONTEXT_CUSTOM
        
        if not kernel32.GetThreadContext(current_thread_handle, ctypes.byref(context)):
            return False
            
        context.EFlags |= 0x100  # Trap flag
        if kernel32.SetThreadContext(current_thread_handle, ctypes.byref(context)):
            return True
        return False

def cleanup_temp_breakpoint(hit_address):
    """Clean up temporary breakpoint used for step over"""
    global temp_breakpoints, current_thread_handle

    if 'temp_breakpoints' not in globals():
        return

    if hit_address in temp_breakpoints:
        dr_num = temp_breakpoints[hit_address]
        
        context = CONTEXT64()
        context.ContextFlags = CONTEXT_CUSTOM
        
        if kernel32.GetThreadContext(current_thread_handle, ctypes.byref(context)):
            # Désactiver le breakpoint
            setattr(context, f"Dr{dr_num}", 0)
            local_enable_bit = dr_num * 2
            context.Dr7 &= ~(1 << local_enable_bit)
            
            if kernel32.SetThreadContext(current_thread_handle, ctypes.byref(context)):
                append_to_console(f"[DEBUG] Temporary breakpoint cleaned up from Dr{dr_num}")
            
        del temp_breakpoints[hit_address]

def on_double_click(event):
    global selected_label
    label = event.widget

    # Réinitialiser l'ancien label s'il y en a un
    if selected_label and selected_label != event.widget:
        selected_label.config(bg="#1e1e1e")

    # Appliquer la nouvelle sélection
    selected_label = event.widget
    selected_label.config(bg="#333366")

    function_window = tk.Toplevel(root)
    function_window.title("EduDbg - Simple PE Debugger")
    function_window.geometry("720x480")
    function_window.iconbitmap("./edudbg.ico")

    main_frame = tk.Frame(function_window, bg="#2e2e2e")
    main_frame.pack(fill="both", expand=True)

    center_frame = tk.Frame(main_frame, bd=2, relief="sunken", bg="#1e1e1e")
    center_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

    tk.Label(center_frame, text=f"Disassembly of {label['text']}", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e").pack(pady=(10, 0))
    view = tk.Text(center_frame, height=22, state="disabled", font=("Courier New", 9),
                        bg="#2d2d2d", fg="white", insertbackground="white")
    view.pack(fill="both", expand=True, pady=(5, 2), padx=5)
    
    instructions = disassemble_at(process_info.hProcess, get_real_address(current_file, process_info.hProcess, f"{label['text']}")) 
    disasm_text = "\n".join(instructions)

    set_text_view(view, disasm_text)

def get_module_base_address(hProcess):
    """Get the base address of the main module"""
    pbi = PROCESS_BASIC_INFORMATION()
    return_length = ctypes.c_uint32()

    status = ntdll.NtQueryInformationProcess(
        hProcess, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(return_length)
    )

    if status != 0:
        return None

    peb = PEB()
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        hProcess, ctypes.c_void_p(pbi.PebBaseAddress), ctypes.byref(peb),
        ctypes.sizeof(peb), ctypes.byref(bytes_read)
    )

    if not success:
        return None

    return peb.ImageBaseAddress

def get_real_address(path, hProcess, function_name):
    """Get the real address of a function in the loaded process"""
    binary = lief.parse(path)
    main_offset = 0

    for symbol in binary.symbols:
        if symbol.name == function_name:
            main_offset = symbol.value
            break

    text_section = next((s for s in binary.sections if s.name == ".text"), None)
    if not text_section:
        return None
        
    text_offset = text_section.virtual_address
    base_address = get_module_base_address(hProcess)

    if base_address is None:
        return None

    return base_address + text_offset + main_offset

def get_function_name(path, addr, hProcess):
    function = get_user_functions(path)
    for name in function:
        if get_real_address(path, hProcess, name) == int(addr, 16):
            return name

def disassemble_at(hProcess, address, size=64):
    global current_file
    """Disassemble code at a given address"""
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t(0)

    if not kernel32.ReadProcessMemory(hProcess, ctypes.c_void_p(address), buffer, size, ctypes.byref(bytes_read)):
        return [f"Failed to read memory at 0x{address:x}"]

    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True

    def is_valid_hex(var):
        try:
            int(var, 16)
            return True
        except (ValueError, TypeError):
            return False
    instructions = []
    for instr in md.disasm(buffer.raw[:bytes_read.value], address):

        if instr.mnemonic == "call" and is_valid_hex(instr.op_str):
            if get_function_name(current_file, instr.op_str, hProcess) != None:
                instructions.append(f"0x{instr.address:x}\t{instr.mnemonic}\t{instr.op_str} ; <{get_function_name(current_file, instr.op_str, hProcess)}>")
            else:
                instructions.append(f"0x{instr.address:x}\t{instr.mnemonic}\t{instr.op_str}")
        else:
            instructions.append(f"0x{instr.address:x}\t{instr.mnemonic}\t{instr.op_str}")
        if instr.mnemonic == "ret":
            break
    
    return instructions

def append_to_console(text):
    """Add text to the debug console"""
    debug_console.config(state="normal")
    debug_console.insert("end", text + "\n")
    debug_console.see("end")
    debug_console.config(state="disabled")

def set_text_view(widget, text):
    """Set text in a text widget"""
    widget.config(state="normal")
    widget.delete(1.0, "end")
    widget.insert("end", text)
    widget.config(state="disabled")

def update_registers():
    """Update the registers view in two columns and add flags"""
    if not current_context:
        return

    reg_text = ""

    # Registres colonne de gauche et droite, sans liste de compréhension
    reg_text += f"RAX: {current_context.Rax:#018x}    RBX: {current_context.Rbx:#018x}\n"
    reg_text += f"RCX: {current_context.Rcx:#018x}    RDI: {current_context.Rdi:#018x}\n"
    reg_text += f"RDX: {current_context.Rdx:#018x}    RIP: {current_context.Rip:#018x}\n"
    reg_text += f"RSI: {current_context.Rsi:#018x}    RSP: {current_context.Rsp:#018x}\n"
    reg_text += f"R8 : {current_context.R8:#018x}    R9 : {current_context.R9:#018x}\n"
    reg_text += f"R10: {current_context.R10:#018x}    R11: {current_context.R11:#018x}\n"
    reg_text += f"R12: {current_context.R12:#018x}    R13: {current_context.R13:#018x}\n"
    reg_text += f"R14: {current_context.R14:#018x}    R15: {current_context.R15:#018x}\n"
    reg_text += f"RBP: {current_context.Rbp:#018x}\n"

    # Extraction manuelle des flags
    flags = current_context.EFlags
    cf = (flags >> 0) & 1
    pf = (flags >> 2) & 1
    af = (flags >> 4) & 1
    zf = (flags >> 6) & 1
    sf = (flags >> 7) & 1
    tf = (flags >> 8) & 1
    _if = (flags >> 9) & 1
    df = (flags >> 10) & 1
    of = (flags >> 11) & 1

    # Affichage des flags
    reg_text += f"FLAGS: CF={cf} PF={pf} AF={af} ZF={zf} SF={sf} TF={tf} IF={_if} DF={df} OF={of}"

    set_text_view(registers_view, reg_text)

def get_user_functions(path):
    pe = lief.parse(path)
    
    symboles = []

    # Parcours des symboles
    for symbole in pe.symbols:
        nom = symbole.name
        if (
            nom
            and "." not in nom
            and "_" not in nom
        ):
            symboles.append(nom)

    return symboles

def update_stack():
    """Update the stack view"""
    if not current_context or not process_info:
        return
    
    stack_text = ""
    for i in range(10):
        buffer = ctypes.create_string_buffer(8)
        bytes_read = ctypes.c_size_t(0)
        addr = current_context.Rsp + (i * 8)
        if kernel32.ReadProcessMemory(process_info.hProcess, ctypes.c_void_p(addr), buffer, 8, ctypes.byref(bytes_read)):
            val = int.from_bytes(buffer.raw, 'little')
            stack_text += f"0x{addr:018x} | {val:#018x}\n"
        else:
            stack_text += f"0x{addr:018x} | [Read Error]\n"
    
    set_text_view(stack_view, stack_text)

def update_hex(addr):
    """Update the stack view"""
    if not current_context or not process_info:
        return
    
    try:
        num_lines = 20  # Show more lines in dedicated hex view
        
        # Clear the hex view and prepare for new content
        hex_view.config(state="normal")
        hex_view.delete(1.0, "end")
        
        hex_output = ""
        for i in range(num_lines):
            read_addr = addr + (i * 16)
            buffer = ctypes.create_string_buffer(16)
            bytes_read = ctypes.c_size_t(0)

            if kernel32.ReadProcessMemory(process_info.hProcess, ctypes.c_void_p(read_addr), buffer, 16, ctypes.byref(bytes_read)):
                hex_bytes = ' '.join(f'{b:02x}' for b in buffer.raw)
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in buffer.raw)
                hex_output += f"0x{read_addr:016x} | {hex_bytes:<48} | {ascii_str}\n"
            else:
                hex_output += f"0x{read_addr:016x} | [Read Error]\n"
        
        # Display in hex_view instead of console
        hex_view.insert("end", hex_output)
        hex_view.config(state="disabled")
            
    except ValueError:
        append_to_console("[!] Adresse invalide")

def update_disassembly():
    """Update the disassembly view with colors"""
    if not current_context or not process_info:
        return
    
    instructions = disassemble_at(process_info.hProcess, current_context.Rip, 128)
    
    memory_view.config(state="normal")
    memory_view.delete(1.0, "end")
    
    # Insérer chaque ligne et la colorier
    for i, instruction in enumerate(instructions, 1):
        memory_view.insert("end", instruction + "\n")
        colorize_instruction(memory_view, instruction, i, current_context.Rip)
    
    memory_view.config(state="disabled")

def cleanup_current_session():
    """Nettoie complètement la session de debug actuelle pour permettre le chargement d'un nouveau fichier"""
    global process_info, current_file, is_running, is_paused, current_context
    global current_thread_handle, backup_Dr, backup_Dr7, continue_event
    global breakpoints, main_addr, addr_str
    
    append_to_console("[INFO] Cleaning up current debug session...")
    
    # 1. Arrêter la boucle de debug
    if is_running:
        is_running = False
        is_paused = False
        if continue_event:
            continue_event.set()  # Débloquer la boucle si elle attend
    
    # 2. Terminer le processus en cours s'il existe
    if process_info:
        try:
            # Fermer le handle du thread principal
            if process_info.hThread:
                kernel32.CloseHandle(process_info.hThread)
            
            # Terminer le processus
            if process_info.hProcess:
                kernel32.TerminateProcess(process_info.hProcess, 0)
                # Attendre que le processus se termine proprement
                kernel32.WaitForSingleObject(process_info.hProcess, 2000)  # 2 secondes max
                kernel32.CloseHandle(process_info.hProcess)
                
            append_to_console(f"[+] Process {process_info.dwProcessId} terminated")
            
        except Exception as e:
            append_to_console(f"[!] Error terminating process: {e}")
    
    # 3. Fermer le handle du thread actuel s'il existe
    if current_thread_handle:
        try:
            kernel32.CloseHandle(current_thread_handle)
        except Exception as e:
            append_to_console(f"[!] Error closing thread handle: {e}")
    
    # 4. Réinitialiser toutes les variables globales
    process_info = None
    current_file = None
    is_running = False
    is_paused = False
    current_context = None
    current_thread_handle = None
    backup_Dr = [0, 0, 0, 0]
    backup_Dr7 = 0
    continue_event = None
    breakpoints = {}
    main_addr = 0
    addr_str = 0
    
    # 5. Nettoyer l'interface utilisateur
    try:
        # Vider la liste des breakpoints
        breakpoint_list.delete(0, tk.END)
        
        # Vider les champs d'input
        bp_input.delete(0, tk.END)
        hx_input.delete(0, tk.END)
        
        # Nettoyer les vues de texte
        set_text_view(registers_view, "")
        set_text_view(stack_view, "")
        set_text_view(memory_view, "")
        set_text_view(hex_view, "")
        
        # Nettoyer la liste des fonctions
        function_view.config(state="normal")
        function_view.delete(0, tk.END)
        # Supprimer tous les widgets enfants (les labels des fonctions)
        for widget in function_view.winfo_children():
            widget.destroy()
        function_view.config(state="disabled")
        
        append_to_console("[+] UI cleaned up successfully")
        
    except Exception as e:
        append_to_console(f"[!] Error cleaning UI: {e}")
    
    # 6. Petite pause pour s'assurer que tout est bien nettoyé
    time.sleep(1)
    
    append_to_console("[+] Session cleanup completed - Ready for new file")
    append_to_console("-" * 60)

def start_process(path):
    """Start the process in suspended mode and continue until main breakpoint"""
    global process_info, current_file, main_addr, addr_str

    breakpoint_list.delete(0,4)

    current_file = path
    startupinfo = STARTUPINFO()
    proc_info = PROCESS_INFORMATION()
    startupinfo.cb = ctypes.sizeof(startupinfo)

    created = kernel32.CreateProcessW(
        path, None, None, None, False,
        DEBUG_PROCESS | CREATE_SUSPENDED | CREATE_NEW_CONSOLE,
        None, None,
        ctypes.byref(startupinfo),
        ctypes.byref(proc_info)
    )

    if not created:
        error_msg = f"CreateProcess failed: {ctypes.GetLastError()}"
        append_to_console(f"[!] {error_msg}")
        return False, error_msg

    process_info = proc_info

    # Obtenir l'adresse réelle de main
    main_addr = get_real_address(path, process_info.hProcess, "main")
    append_to_console(f"[!] Adresse de main : {main_addr:#018x}")

    # Mettre breakpoint hardware sur le thread principal (AVANT resume)
    context = CONTEXT64()
    context.ContextFlags = CONTEXT_CUSTOM

    if kernel32.GetThreadContext(process_info.hThread, ctypes.byref(context)):
        context.Dr0 = main_addr
        context.Dr7 |= 0x1  # Active le breakpoint sur Dr0
        if not kernel32.SetThreadContext(process_info.hThread, ctypes.byref(context)):
            append_to_console("[!] SetThreadContext failed")
        else:
            breakpoints[main_addr] = True
    else:
        append_to_console("[!] GetThreadContext failed")

    # Maintenant seulement on relance le thread principal
    kernel32.ResumeThread(process_info.hThread)

    append_to_console(f"[+] Started process {path} with PID {process_info.dwProcessId}")
    append_to_console("[*] Waiting for breakpoint to hit main...")

    # Continue automatiquement jusqu'à ce que le breakpoint sur main soit atteint
    while True:
        debug_event = DEBUG_EVENT()
        if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 1000):
            continue

        if debug_event.dwDebugEventCode == EXCEPTION_DEBUG_EVENT:
            thread_handle = kernel32.OpenThread(0x1F03FF, False, debug_event.dwThreadId)
            if thread_handle:
                context = CONTEXT64()
                context.ContextFlags = CONTEXT_CUSTOM
                if kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                    if context.Dr6 & 0x1:  # Breakpoint Dr0 hit
                        append_to_console(f"[+] Breakpoint hit at main: RIP={context.Rip:#018x}")
                        addr_str=context.Rip
                        update_hex(addr_str)
                        context.Dr6 = 0  # Clear debug status register
                        kernel32.SetThreadContext(thread_handle, ctypes.byref(context))
                        kernel32.CloseHandle(thread_handle)
                        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)
                        break
                kernel32.CloseHandle(thread_handle)

        kernel32.ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, DBG_CONTINUE)

    functions = get_user_functions(path)   

    function_view.config(state="normal")

    for func in functions:
        function_view.insert("end", func + "\n")
        label = tk.Label(function_view, text=f"{func}", font=("Segoe UI", 10), fg="white", bg="#1e1e1e", justify='left', anchor='w')
        label.pack(fill="x")
        label.bind("<Double-Button-1>", on_double_click)

    function_view.config(state="disabled")

    return True, "Process initialized successfully"

def debug_loop():
    """Main debug loop with GUI button detection"""
    global is_running, is_paused, current_context, current_thread_handle
    global backup_Dr, backup_Dr7, continue_event, addr_str
    
    if not process_info:
        return

    debug_event = DEBUG_EVENT()
    context = CONTEXT64()
    context.ContextFlags = CONTEXT_CUSTOM

    # Pour restaurer les breakpoints si besoin
    backup_Dr = [0, 0, 0, 0]
    backup_Dr7 = 0

    exe = pefile.PE(current_file)
    last_rip = 0
    running = True

    while running and is_running:
        if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 100):
            continue

        code = debug_event.dwDebugEventCode
        thread_id = debug_event.dwThreadId

        if code == EXCEPTION_DEBUG_EVENT:
            thread_handle = kernel32.OpenThread(0x1F03FF, False, thread_id)
            if not thread_handle:
                append_to_console(f"[!] Failed to open thread {thread_id}")
                break

            current_thread_handle = thread_handle
            context.ContextFlags = CONTEXT_CUSTOM
            
            if kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                current_context = context

                if context.Dr6 & 0x0F:
                    # Clear Dr6 and disable breakpoints temporarily
                    context.Dr6 = 0
                    temp_Dr7 = context.Dr7
                    context.Dr7 = 0
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(context))
                else:
                    # Restore breakpoints if needed
                    context.Dr0, context.Dr1, context.Dr2, context.Dr3 = backup_Dr
                    context.Dr7 = backup_Dr7
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(context))

                if context.Rip == last_rip:
                    append_to_console(f"[!] RIP hasn't changed; breaking out of potential infinite loop.")
                    kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)
                    kernel32.CloseHandle(thread_handle)
                    continue
                last_rip = context.Rip

                # Update GUI
                update_registers()
                update_stack()
                update_disassembly()
                update_hex(addr_str)

                is_paused = True
                continue_event.clear()
                
                while is_paused and is_running:
                    # Check for GUI button presses while waiting
                    button = check_button_pressed()
                    if button:                        
                        if button == "step":
                            context.EFlags |= 0x100  # Trap flag
                            if kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                                is_paused = False
                                kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)
                        elif button == "step_over":
                            if step_over():
                                is_paused = False
                                kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)
                        
                        elif button == "continue":
                            is_paused = False
                            kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)
                            
                        elif button == "stop":
                            cleanup_current_session()
                            is_paused = False
                            running = False
                            break

                        elif button == "search_hex":
                            addr_str = int(hx_input.get().strip(), 16)
                            update_hex(addr_str)

                        elif button == "add_breakpoint":
                            append_to_console("[DEBUG] Adding Breakpoint")
                            
                            bp_address_str = bp_input.get().strip()
                            
                            if not bp_address_str:
                                append_to_console("[!] Please enter a breakpoint address")
                                continue  # Continue la boucle au lieu de return
                            
                            try:
                                if bp_address_str.startswith('0x') or bp_address_str.startswith('0X'):
                                    bp = int(bp_address_str, 16)
                                elif bp_address_str.isdigit():
                                    bp = int(bp_address_str)
                                else:
                                    bp = int(bp_address_str, 16)
                                
                                free_dr = -1
                                for i in range(4):
                                    if getattr(context, f"Dr{i}") == 0:
                                        free_dr = i
                                        break
                                
                                if free_dr == -1:
                                    append_to_console("[!] All hardware breakpoints are in use (max 4).")
                                    continue
                                
                                setattr(context, f"Dr{free_dr}", bp)
                                
                                local_enable_bit = free_dr * 2
                                
                                context.Dr7 |= (1 << local_enable_bit)
                                
                                condition_base = 16 + (free_dr * 4)
                                size_base = 24 + (free_dr * 2)
                                
                                context.Dr7 &= ~(0x3 << condition_base)  # Clear condition bits
                                context.Dr7 &= ~(0x3 << size_base)       # Clear size bits
                                
                                if kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                                    append_to_console(f"[+] Breakpoint set at {bp:#018x} in Dr{free_dr}")
                                    
                                    backup_Dr[free_dr] = bp
                                    backup_Dr7 = context.Dr7
                                    
                                    breakpoints[bp] = True
                                    
                                    breakpoint_list.insert(tk.END, f"Dr{free_dr}: {bp:#018x}")
                                    
                                    bp_input.delete(0, tk.END)
                                else:
                                    append_to_console("[!] Failed to set context with new breakpoint.")
                                    setattr(context, f"Dr{free_dr}", 0)
                                    
                            except ValueError:
                                append_to_console(f"[!] Invalid address format: '{bp_address_str}'. Use hex (0x1000 or 1000) or decimal.")

                    if continue_event.wait(timeout=0.1):
                        break

            else:
                append_to_console("[!] Failed to get thread context")

            kernel32.CloseHandle(thread_handle)

        elif code == EXIT_PROCESS_DEBUG_EVENT:
            append_to_console(f"\n[+] Process {debug_event.dwProcessId} has exited.")
            running = False
            is_running = False

        if running and is_running:
            kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)
    
    # Cleanup
    if current_thread_handle:
        kernel32.CloseHandle(current_thread_handle)
        current_thread_handle = None

def open_file():
    """Open file dialog and start debugging"""
    global continue_event
    
    # Nettoyer la session actuelle si elle existe
    if process_info is not None or is_running:
        cleanup_current_session()
    
    file_path = filedialog.askopenfilename(
        title="Select PE file",
        filetypes=[("Executable files", "*.exe"), ("All files", "*.*")]
    )
    if file_path:
        append_to_console(f"[INFO] File selected: {file_path}")
        
        continue_event = threading.Event()
        
        def start_debug_thread():
            global is_running
            is_running = True
            success, message = start_process(file_path)
            if success:
                append_to_console(f"[SUCCESS] {message}")
                debug_loop()
            else:
                append_to_console(f"[ERROR] {message}")
                is_running = False
        
        debug_thread = threading.Thread(target=start_debug_thread, daemon=True)
        debug_thread.start()

def setup_disasm_colors(text_widget):
    """Configure les couleurs pour le désassemblage"""
    # Adresses
    text_widget.tag_config("address", foreground="#8CDCDA")  # Cyan clair
    
    # Instructions
    text_widget.tag_config("mnemonic_jump", foreground="#FF6B6B")     # Rouge pour jumps
    text_widget.tag_config("mnemonic_call", foreground="#4ECDC4")     # Turquoise pour calls
    text_widget.tag_config("mnemonic_ret", foreground="#45B7D1")      # Bleu pour returns
    text_widget.tag_config("mnemonic_mov", foreground="#96CEB4")      # Vert pour mov
    text_widget.tag_config("mnemonic_cmp", foreground="#FFEAA7")      # Jaune pour cmp/test
    text_widget.tag_config("mnemonic_push", foreground="#DDA0DD")     # Violet pour push/pop
    text_widget.tag_config("mnemonic_default", foreground="#F8F8F2")  # Blanc pour autres
    
    # Opérandes
    text_widget.tag_config("register", foreground="#BD93F9")          # Violet pour registres
    text_widget.tag_config("immediate", foreground="#FFB86C")         # Orange pour immédiats
    text_widget.tag_config("memory", foreground="#50FA7B")            # Vert pour mémoire
    text_widget.tag_config("comment", foreground="#6272A4")           # Gris pour commentaires
    
    # Breakpoint highlight
    text_widget.tag_config("breakpoint_line", background="#8B0000")   # Rouge foncé

def colorize_instruction(text_widget, line, line_number, current_rip):
    """Colorise une ligne d'instruction"""
    global breakpoints
    
    parts = line.split('\t')
    if len(parts) < 2:
        return
    
    address_part = parts[0]
    mnemonic = parts[1] if len(parts) > 1 else ""
    operands = parts[2] if len(parts) > 2 else ""
    
    start_pos = f"{line_number}.0"
    
    # Colorier l'adresse
    addr_end = f"{line_number}.{len(address_part)}"
    text_widget.tag_add("address", start_pos, addr_end)
    
    mnemonic_start = f"{line_number}.{len(address_part) + 1}"
    mnemonic_end = f"{line_number}.{len(address_part) + 1 + len(mnemonic)}"
    
    if mnemonic in ["jmp", "je", "jne", "jz", "jnz", "jl", "jle", "jg", "jge", "ja", "jae", "jb", "jbe", "jo", "jno", "js", "jns", "jc", "jnc"]:
        text_widget.tag_add("mnemonic_jump", mnemonic_start, mnemonic_end)
    elif mnemonic == "call":
        text_widget.tag_add("mnemonic_call", mnemonic_start, mnemonic_end)
    elif mnemonic in ["ret", "retn", "retf"]:
        text_widget.tag_add("mnemonic_ret", mnemonic_start, mnemonic_end)
    elif mnemonic in ["mov", "movsx", "movzx", "lea"]:
        text_widget.tag_add("mnemonic_mov", mnemonic_start, mnemonic_end)
    elif mnemonic in ["cmp", "test"]:
        text_widget.tag_add("mnemonic_cmp", mnemonic_start, mnemonic_end)
    elif mnemonic in ["push", "pop"]:
        text_widget.tag_add("mnemonic_push", mnemonic_start, mnemonic_end)
    else:
        text_widget.tag_add("mnemonic_default", mnemonic_start, mnemonic_end)
    
    # Colorier les opérandes
    if operands:
        operands_start = f"{line_number}.{len(address_part) + 1 + len(mnemonic) + 1}"
        colorize_operands(text_widget, operands, operands_start, line_number)
    
    # Highlight si c'est l'instruction courante (RIP)
    try:
        line_addr = int(address_part, 16)
        if line_addr == current_rip:
            text_widget.tag_add("breakpoint_line", start_pos, f"{line_number}.end")
    except:
        pass

def colorize_operands(text_widget, operands_text, start_pos, line_number):
    """Colorise les opérandes d'une instruction"""    
    # Registres 64-bit, 32-bit, 16-bit, 8-bit
    register_pattern = r'\b(rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|r8|r9|r10|r11|r12|r13|r14|r15|eax|ebx|ecx|edx|esi|edi|ebp|esp|ax|bx|cx|dx|si|di|bp|sp|al|ah|bl|bh|cl|ch|dl|dh)\b'
    
    # Valeurs immédiates (hex et décimal)
    immediate_pattern = r'\b(0x[0-9a-fA-F]+|\d+)\b'
    
    # Références mémoire [...]
    memory_pattern = r'\[[^\]]+\]'
    
    # Commentaires ; ...
    comment_pattern = r';.*$'
    
    base_col = int(start_pos.split('.')[1])
    
    # Colorier les commentaires en premier
    for match in re.finditer(comment_pattern, operands_text):
        start_col = base_col + match.start()
        end_col = base_col + match.end()
        text_widget.tag_add("comment", f"{line_number}.{start_col}", f"{line_number}.{end_col}")
    
    # Colorier les références mémoire
    for match in re.finditer(memory_pattern, operands_text):
        start_col = base_col + match.start()
        end_col = base_col + match.end()
        text_widget.tag_add("memory", f"{line_number}.{start_col}", f"{line_number}.{end_col}")
    
    # Colorier les registres
    for match in re.finditer(register_pattern, operands_text, re.IGNORECASE):
        start_col = base_col + match.start()
        end_col = base_col + match.end()
        text_widget.tag_add("register", f"{line_number}.{start_col}", f"{line_number}.{end_col}")
    
    # Colorier les valeurs immédiates
    for match in re.finditer(immediate_pattern, operands_text):
        start_col = base_col + match.start()
        end_col = base_col + match.end()
        text_widget.tag_add("immediate", f"{line_number}.{start_col}", f"{line_number}.{end_col}")

def show_tooltip(event, text):
    """Affiche un tooltip à la position de la souris"""
    widget = event.widget
    x = widget.winfo_rootx() + 25
    y = widget.winfo_rooty() + 25
    
    tooltip_window = tk.Toplevel(widget)
    tooltip_window.wm_overrideredirect(True)
    tooltip_window.wm_geometry(f"+{x}+{y}")
    tooltip_window.configure(bg="#ffffe0")
    
    label = tk.Label(tooltip_window, text=text, justify=tk.LEFT,
                    background="#ffffe0", relief=tk.SOLID, borderwidth=1,
                    font=("Segoe UI", "8", "normal"), wraplength=300)
    label.pack(ipadx=1)
    
    widget.tooltip_window = tooltip_window

def hide_tooltip(event):
    """Cache le tooltip"""
    widget = event.widget
    if hasattr(widget, 'tooltip_window'):
        widget.tooltip_window.destroy()
        delattr(widget, 'tooltip_window')

def add_tooltip_to_label(label, tooltip_text):
    """Ajoute un tooltip à un label existant"""
    current_text = label.cget("text")
    label.config(text=current_text + "", cursor="hand2")
    label.bind("<Enter>", lambda e: show_tooltip(e, tooltip_text))
    label.bind("<Leave>", hide_tooltip)

def create_gui():
    """Create the GUI with modern styled buttons"""
    global root, debug_console, registers_view, stack_view, memory_view
    global breakpoint_list, bp_input, hx_input, hex_view, function_view

    root = tk.Tk()
    root.title("EduDbg - Simple PE Debugger")
    root.geometry("1280x720")
    root.state('zoomed') 
    root.iconbitmap("./edudbg.ico")

    # Menu
    menubar = tk.Menu(root)
    file_menu = tk.Menu(menubar, tearoff=0)
    file_menu.add_command(label="Open file...", command=open_file)
    file_menu.add_command(label="Quit", command=root.quit)
    menubar.add_cascade(label="File", menu=file_menu)

    root.config(menu=menubar)

    # Beautiful buttons
    def styled_button(parent, text, color, command):
        return tk.Button(
            parent, text=text, command=command,
            bg=color, fg="white", activebackground="#222222", activeforeground="white",
            font=("Segoe UI", 9, "bold"), bd=0, relief="ridge", padx=10, pady=5
        )

    # Main frame
    main_frame = tk.Frame(root, bg="#2e2e2e")
    main_frame.pack(fill="both", expand=True)

    # Left panel
    left_frame = tk.Frame(main_frame, width=250, bd=2, relief="sunken", bg="#1e1e1e")
    left_frame.pack(side="left", fill="y", padx=5, pady=5)
    left_frame.pack_propagate(False)

    # Breakpoints section
    bp_label = tk.Label(left_frame, text="Breakpoints", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e")
    bp_label.pack(pady=(5, 0))
    add_tooltip_to_label(bp_label, "Breakpoints:\n• Ajoutez une adresse hexadécimale (ex: 0x401000)\n• Maximum 4 breakpoints hardware\n• Double-cliquez pour supprimer")
    
    breakpoint_list = tk.Listbox(left_frame, height=8, bg="#2d2d2d", fg="white", selectbackground="#2d2d2d", relief="flat")
    breakpoint_list.pack(fill="x", pady=5, padx=5)

    bp_frame = tk.Frame(left_frame, bg="#1e1e1e")
    bp_frame.pack(fill="x", pady=5, padx=5)
    bp_input = tk.Entry(bp_frame, bg="#2d2d2d", fg="white", relief="flat")
    bp_input.pack(side="left", fill="x", expand=True, padx=(0, 5))

    styled_button(bp_frame, "Add", "#650000", on_break_button).pack(side='right')

    # Debug controls section
    debug_label = tk.Label(left_frame, text="Debug Controls", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e")
    debug_label.pack(pady=(10, 5))
    add_tooltip_to_label(debug_label, "Contrôles de débogage:\n• Step: Exécute une instruction\n• Continue: Reprend l'exécution\n• Stop: Arrête le processus")

    control_frame = tk.Frame(left_frame, bg="#1e1e1e")
    control_frame.pack(fill="x", padx=5)

    styled_button(control_frame, "Step", "#1b699d", on_step_button).pack(fill="x", pady=3)
    styled_button(control_frame, "Step Over", "#d7ad59", on_step_over_button).pack(fill="x", pady=3)
    styled_button(control_frame, "Continue", "#1c904c", on_continue_button).pack(fill="x", pady=3)
    styled_button(control_frame, "Stop", "#b02010", on_stop_button).pack(fill="x", pady=3)

    function_view = tk.Listbox(left_frame, bg="#1e1e1e", fg="white", font=("Segoe UI", 10))
    function_view.pack(side="right", fill="both", expand=True)

    # Center panel - Disassembly
    center_frame = tk.Frame(main_frame, bd=2, relief="sunken", bg="#1e1e1e")
    center_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

    # Disassembly section
    disasm_label = tk.Label(center_frame, text="Disassembly", font=("Segoe UI", 14, "bold"), fg="white", bg="#1e1e1e")
    disasm_label.pack(pady=(10, 0))
    add_tooltip_to_label(disasm_label, "Désassemblage:\n• Affiche les instructions à partir de RIP\n• Les appels de fonction sont annotés\n• S'arrête au premier 'ret'")
    
    memory_view = tk.Text(center_frame, height=22, state="disabled", font=("Courier New", 9), bg="#2d2d2d", fg="white", insertbackground="white")
    memory_view.pack(fill="both", expand=True, pady=(5, 2), padx=5)
    setup_disasm_colors(memory_view)

    # HexView section
    hex_label = tk.Label(center_frame, text="HexView", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e")
    hex_label.pack(pady=(5, 0))
    add_tooltip_to_label(hex_label, "Vue hexadécimale:\n• Entrez une adresse dans le champ\n• Cliquez 'Search' pour naviguer\n• Format: adresse | hex | ASCII")
    
    hex_view = tk.Text(center_frame, height=15, state="disabled", font=("Courier New", 9), bg="#2d2d2d", fg="white", insertbackground="white")
    hex_view.pack(fill="both", expand=True, pady=(2, 10), padx=5)

    hx_frame = tk.Frame(center_frame, bg="#1e1e1e")
    hx_frame.pack(fill="x", pady=5, padx=5)
    hx_input = tk.Entry(hx_frame, bg="#2d2d2d", fg="white", relief="flat")
    hx_input.pack(side="left", fill="x", expand=True, padx=(0, 5))
    styled_button(hx_frame, "Search", "#6d6d6d", on_search_hex_button).pack(side='right')

    # Right panel
    right_frame = tk.Frame(main_frame, width=475, bd=2, relief="sunken", bg="#1e1e1e")
    right_frame.pack(side="left", fill="y", padx=5, pady=8)
    right_frame.pack_propagate(False)

    # Registers section
    reg_label = tk.Label(right_frame, text="Registers", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e")
    reg_label.pack(pady=(10, 0))
    add_tooltip_to_label(reg_label, "Registres:\nZones mémoire ultra-rapides du processeur.\n\n• RIP : adresse de la prochaine instruction\n• RSP : Pointeur vers le sommet de la pile.\n• RAX, RBX... : registres généraux\n• RSI, RDI : Utilisés pour passer des arguments\naux fonctions\n\nFLAGS : état (flags ZF, CF...)")
    
    registers_view = tk.Text(right_frame, height=10, width=60, state="disabled", font=("Courier New", 9), bg="#2d2d2d", fg="white", insertbackground="white")
    registers_view.pack(fill="x", pady=5)

    # Stack section
    stack_label = tk.Label(right_frame, text="Stack", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e")
    stack_label.pack(pady=(10, 0))
    add_tooltip_to_label(stack_label, "Pile d'exécution:\nStructure LIFO utilisée pour les appels de fonctions, variables locales et retours.\n\n• Contrôlée par RSP et RBP.\n• Gérée avec PUSH / POP.")
    
    stack_view = tk.Text(right_frame, height=10, width=60, state="disabled", font=("Courier New", 9), bg="#2d2d2d", fg="white", insertbackground="white")
    stack_view.pack(fill="x", pady=5)

    # Debug console section
    console_label = tk.Label(right_frame, text="Debug Console", font=("Segoe UI", 10, "bold"), fg="white", bg="#1e1e1e")
    console_label.pack(pady=(10, 0))
    add_tooltip_to_label(console_label, "Console de débogage:\n• Messages d'état du debugger\n• Erreurs et confirmations\n• Log des événements de debug")

    # Frame pour la console
    console_frame = tk.Frame(right_frame, bg="#1e1e1e")
    console_frame.pack(fill="both", expand=True, pady=(2, 5))

    debug_console = tk.Text(console_frame, width=60, state="disabled", font=("Courier New", 9), bg="#2d2d2d", fg="white", insertbackground="white")
    debug_console.pack(fill="both", expand=True)

    append_to_console("[INFO] EduDbg initialized - Load a PE file to start debugging")

def main():
    """Main function"""
    create_gui()
    root.mainloop()

if __name__ == "__main__":
    main()