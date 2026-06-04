# RDB

## Raxyen Debugger

RDB (Raxyen Debugger) is a lightweight debugger for Linux written in C as part of my Engineering Thesis in Computer Science at Nicolaus Copernicus University (NCU) in Toruń, Poland.

The project aims to explore low-level software development, process tracing, debugging mechanisms, and x86-64 instruction decoding by implementing a debugger from scratch using Linux system interfaces such as ptrace().

![UI]("rdb tui.png")

# Features

## Implemented

* Live CPU register view (RAX, RBX, RCX, RDX, RSI, RDI, RSP, RBP, RIP, R8-R15)
* Stack memory inspection relative to the current stack pointer
* Live execution tracing using single-stepping
* Instruction history view
* Colored terminal interface
* Basic x86-64 instruction disassembly
* Support for:
    * REX prefixes
    * ModR/M decoding
    * SIB decoding
    * RIP-relative addressing
    * Relative jumps and calls

## In Progress

* Extended x86-64 instruction coverage
* Breakpoint support
* Improved disassembler accuracy
* More advanced terminal user interface (TUI)
* Memory inspection tools
* Better instruction formatting and syntax highlighting

# Technologies

* C17
* Linux
* ptrace()
* x86-64 Assembly
* ELF Executables

# Purpose

The goal of this project is educational. Rather than relying on existing libraries such as Capstone, the debugger implements instruction decoding manually to better understand the internal structure of x86-64 machine code and Linux debugging mechanisms.
