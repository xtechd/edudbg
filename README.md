![edudbg](https://github.com/user-attachments/assets/c791ff98-c91d-495b-8af1-477bc9cc6f1c)

# Getting Started

Welcome to the documentation for your Windows Debugger. This tool allows you to debug specific compiled executables at the instruction level using a clean and simple user interface.

> ⚠️ **Note**: This debugger is designed to work with specific compiled files. Example binaries are available on the GitHub repository for testing and demonstration purposes.

## Installation
```bash
python3 -m pip install -r requirement.txt
```

## User Interface

The debugger interface provides the following controls:

- **Drop-down Menu (File)**: Select the executable file you want to debug.

- **Step Into Button**: Execute the program one instruction at a time.

- **Continue Button**: Resume execution until the next breakpoint is hit.

- **Breakpoint Address Input**: Enter the memory address where you want to set a breakpoint.

- **Stop Button**: Halt the currently running program.

> 🔹 **Breakpoint Limit**: You can set a maximum of four breakpoints at a time. Trying to add more will result in an error or ignore the additional request.

![Edudbg](https://github.com/user-attachments/assets/f513a851-49db-4e53-82ff-a18c4184d2b1)

## Debugging Features

The debugger offers several core features to assist with low-level program analysis:

- **Disassembly View**: Displays the disassembled machine code of the current function.

- **Stack Viewer**: Shows the current state of the call stack, helping you understand function nesting and return paths.

- **Register Viewer**: Displays live CPU register values, allowing you to trace data flow and execution logic.

## Example Files

This debugger is built for use with specific compiled formats. For convenience, we’ve provided example files on the GitHub repository that are compatible with this tool. These samples are ideal for learning and testing your debugging workflow.
