import ctypes
import sys
import time
import lief
from ctypes import wintypes

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

CONTEXT_CUSTOM = CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS  # CONTEXT_CONTROL | CONTEXT_INTEGER
CONTEXT_ALL = 0x0010003F

# Windows types
LPVOID = ctypes.c_void_p
DWORD = ctypes.c_uint32
ULONG_PTR = ctypes.c_ulonglong
HANDLE = LPVOID

# Définir les structures nécessaires
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

class MODULEINFO(ctypes.Structure):
    _fields_ = [
        ("lpBaseOfDll", wintypes.LPVOID),
        ("SizeOfImage", wintypes.DWORD),
        ("EntryPoint", wintypes.LPVOID),
    ]

# Windows structures
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
        ("u", ctypes.c_byte * 1600),  # Size for EXCEPTION_DEBUG_INFO etc.
    ]

# 64-bit CONTEXT struct
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

# Load kernel32
kernel32 = ctypes.windll.kernel32
psapi = ctypes.WinDLL('psapi')
ntdll = ctypes.WinDLL('ntdll.dll')

# Définir les prototypes de fonction
ntdll.NtQueryInformationProcess.argtypes = [
    HANDLE,
    ctypes.c_uint32,
    LPVOID,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
]
ntdll.NtQueryInformationProcess.restype = ctypes.c_uint32

def get_module_base_address(hProcess):
    # Obtenir les informations de base du processus
    pbi = PROCESS_BASIC_INFORMATION()
    return_length = ctypes.c_uint32()

    status = ntdll.NtQueryInformationProcess(
        hProcess,
        0,  # ProcessBasicInformation
        ctypes.byref(pbi),
        ctypes.sizeof(pbi),
        ctypes.byref(return_length),
    )

    if status != 0:
        print(f"[!] NtQueryInformationProcess failed with status: {status}")
        return None

    print(f"[DEBUG] PebBaseAddress: {pbi.PebBaseAddress:#x}")

    # Lire la structure PEB
    peb = PEB()
    bytes_read = ctypes.c_size_t(0)

    success = kernel32.ReadProcessMemory(
        hProcess,
        ctypes.c_void_p(pbi.PebBaseAddress),
        ctypes.byref(peb),
        ctypes.sizeof(peb),
        ctypes.byref(bytes_read),
    )

    if not success:
        print(f"[!] ReadProcessMemory failed. GetLastError: {kernel32.GetLastError()}")
        return None

    return peb.ImageBaseAddress


def Start(path):

    binary = lief.parse(path)

    for symbol in binary.symbols:
        if symbol.name == "main":
            print(f"Adresse de main : 0x{symbol.value:x}")
            break

    startupinfo = STARTUPINFO()
    process_info = PROCESS_INFORMATION()
    startupinfo.cb = ctypes.sizeof(startupinfo)

    created = kernel32.CreateProcessW(
        path, None, None, None, False,
        DEBUG_PROCESS | CREATE_NEW_CONSOLE,
        None, None,
        ctypes.byref(startupinfo),
        ctypes.byref(process_info)
    )

    if not created:
        print(f"[!] CreateProcess failed: {ctypes.GetLastError()}")
        return 0

    hProcess = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process_info.dwProcessId)
    time.sleep(1)
    base_address = get_module_base_address(process_info.hProcess)
    if base_address is None:
        print("[!] Impossible de récupérer base address")
        return None

    print(f"[+] Base address du module principal: 0x{base_address:x}")

    kernel32.ResumeThread(process_info.hThread)
    print(f"[+] Started process {path} with PID {process_info.dwProcessId}")
    return process_info

def debug_loop(process_info): #0x00007ff9ce5a63b2 addr sur la quel break
    debug_event = DEBUG_EVENT()
    context = CONTEXT64()
    context.ContextFlags = CONTEXT_CUSTOM
    backup_Dr7 = 0
    backup_Dr0 = 0
    backup_Dr1 = 0
    backup_Dr2 = 0
    backup_Dr3 = 0

    last_rip = 0  # Track the last RIP value to detect infinite loop.
    running = True  # Control whether to keep the process running

    while running:
        if not kernel32.WaitForDebugEvent(ctypes.byref(debug_event), 1000):
            continue

        code = debug_event.dwDebugEventCode
        thread_id = debug_event.dwThreadId

        if code == EXCEPTION_DEBUG_EVENT:
            thread_handle = kernel32.OpenThread(0x1F03FF, False, thread_id)
            if not thread_handle:
                print(f"[!] Failed to open thread {thread_id}")
                break

            context.ContextFlags = CONTEXT_CUSTOM
            if kernel32.GetThreadContext(thread_handle, ctypes.byref(context)):
                # Check for infinite loop by comparing RIP.
                if (context.Dr6 & 0x0F): # condition pour ne pas loop sur une breakpoint
                    context.Dr7 = 0
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(context))
                else:
                    context.Dr7 = backup_Dr7
                    context.Dr0 = backup_Dr0
                    context.Dr1 = backup_Dr1
                    context.Dr2 = backup_Dr2
                    context.Dr3 = backup_Dr3
                    kernel32.SetThreadContext(thread_handle, ctypes.byref(context))

                if context.Rip == last_rip:
                    print(f"[!] RIP hasn't changed; breaking out of potential infinite loop.")
                    kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)
                    kernel32.CloseHandle(thread_handle)
                    continue
                last_rip = context.Rip  # Update last RIP value.

                print(f"\n[+] Exception in Thread {thread_id}")
                print("rax={0:#018x} rbx={1:#018x} rcx={2:#018x}".format(context.Rax, context.Rbx, context.Rcx))
                print("rdx={0:#018x} rsi={1:#018x} rdi={2:#018x}".format(context.Rdx, context.Rsi, context.Rdi))
                print("rip={0:#018x} rsp={1:#018x} rbp={2:#018x}".format(context.Rip, context.Rsp, context.Rbp))
                print("r8={0:#018x}  r9={1:#018x} r10={2:#018x}".format(context.R8, context.R9, context.R10))
                print("r11={0:#018x} r12={1:#018x} r13={2:#018x}".format(context.R11, context.R12, context.R13))
                print("r14={0:#018x} r15={1:#018x} eflags={2:#010x}".format(context.R14, context.R15, context.EFlags))
                print("Dr0={0:#018x} Dr1={1:#018x} Dr2={2:#018x} Dr3={3:#018x}".format(context.Dr0, context.Dr1, context.Dr2, context.Dr3))

                # Log the instruction size
                # Here, you would call a disassembler or just log the size
                print(f"[+] Instruction size: Check for multi-byte instruction at RIP={context.Rip:#018x}")

                # Ask for user input

                paused = True
                while paused:
                    user_input = input("[x] Input 's' to step into, 'c' to continue, 'b' to put a breakpoint, 'st' pour afficher la stack, and 'q' to quit : ").strip()

                    if user_input == "st":
                        for i in range(6):
                            buffer = ctypes.create_string_buffer(8)
                            bytes_read = ctypes.c_size_t(0)
                            addr = context.Rsp + (i * 8)
                            success = kernel32.ReadProcessMemory(process_info.hProcess, ctypes.c_void_p(addr), buffer, 8, ctypes.byref(bytes_read))
                            if not success or bytes_read.value != 8:
                                print(f"[!] Failed to read memory at 0x{addr:x}")
                            else:
                                val = int.from_bytes(buffer.raw, 'little')
                                print(f"0x{addr:018x} | {val:#018x}")

                    if user_input == "s":
                        # Step through the next instruction
                        context.EFlags = context.EFlags | 0x100
                        if not kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                            print("[!] Failed to set thread context")
                            running = False
                        else:
                            paused= False
                            kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)

                    elif user_input == "c":
                        # Continue execution until the next exception
                        paused= False
                        kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)

                    elif user_input == "b":
                        bp = int(input("[x] Enter breakpoint address : "), 16)
                        if (not context.Dr0) | (not context.Dr1) | (not context.Dr2) | (not context.Dr3):
                            context.Dr0 = bp         # Adresse à surveiller
                            context.Dr7 |= 0x1             # Active DR0 (bit 0 de DR7)

                            # backup des registre (ils ce font clear une fois que on break dessu... Les petit batard ...)
                            backup_Dr7 = context.Dr7
                            backup_Dr0 = context.Dr0
                            backup_Dr1 = context.Dr1
                            backup_Dr2 = context.Dr2
                            backup_Dr3 = context.Dr3
                            #context.ContextFlags = CONTEXT_CUSTOM
                            if kernel32.SetThreadContext(thread_handle, ctypes.byref(context)):
                                print(f"[+] Breakpoint at {bp:#018x}")
                            else:
                                print("[!] MERDE")
                        else:
                            print("[!] Too many breakpoint (Limit is 4)")
                    elif user_input == "q":
                        print("Exiting debugger.")
                        paused= False
                        running = False  # Exit the debugger loop

            else:
                print("[!] Failed to get thread context")

            kernel32.CloseHandle(thread_handle)

        elif code == EXIT_PROCESS_DEBUG_EVENT:
            print(f"\n[+] Process {debug_event.dwProcessId} has exited. Shutting down debugger.")
            running = False  # Exit the loop and end the Python debugger

        # Keep the debugger alive until exit is requested.
        kernel32.ContinueDebugEvent(debug_event.dwProcessId, thread_id, DBG_CONTINUE)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_exe>")
        sys.exit(1)

    ps_info = Start(sys.argv[1])

    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400

    if ps_info:
        hProcess = kernel32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, ps_info.dwProcessId)
        if not hProcess:
            print("[!] Failed to open process with desired access")
        else:
            print("[+] Got handle with PROCESS_VM_READ access")
            ps_info.hProcess = hProcess  # Remplace le handle dans process_info
    debug_loop(ps_info)
