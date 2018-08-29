#!/usr/bin/python

from pwn import *
import os

s = remote("abc.eatpwnnosleep.com",55555)

for _ in range(100):
  chg = 0
  print _  
  s.recvuntil("TRY")
  s.recvuntil("/100\n")
  f = s.recvuntil("\n")[:-1]
  os.system("rm /tmp/a")
  open("/tmp/a","w").write(f)
  os.system("base64 -d /tmp/a > ./b && chmod 777 ./b")

  addrs = []
  vals = []

  os.system("objdump -M intel -d ./b | grep -5 read | grep atoi | grep call > /tmp/a")
  a=open("/tmp/a").read().split("\n")
  if len(a)!=2:
    exit()
  addr = int(a[0].split(":")[0].strip(),16)
  print hex(addr)

  
  os.system("objdump -M intel -d ./b | grep -10 %s | grep lea | grep rbp > /tmp/a"%(hex(addr)[2:]))
  a = open("/tmp/a").read().split("\n")[0]
  offset = p32(int(a.split("[rbp-")[1].split("]")[0],16)-1)
  
  os.system("objdump -M intel -d ./b | grep -10 %s | grep mov | grep edx > /tmp/a"%(hex(addr)[2:]))
  a = open("/tmp/a").read().split("\n")[0]
  addr = int(a.split(":")[0].strip(),16)
  
  byte = a.split(":")[1].split("mov")[0].strip()
  byte = byte.replace(" ","").decode('hex')
  sz = u32(byte[1:5])
  if sz & 0xff < 2:
    addrs.append(addr+1)
    addrs.append(addr+2)
    vals.append(u8(offset[0]))
    vals.append(u8(offset[1]))
    chg = 1
  else:
    addrs.append(addr+2)
    vals.append(0)
  # First Vuln Done.


  os.system("objdump -M intel -d ./b | grep jge > /tmp/a")
  a = open("/tmp/a").read().split("\n")[0]
  addr = int(a.split(":")[0].strip(),16)

  addrs.append(addr)
  vals.append(0x73)

  # Second Vuln Done.



  os.system("objdump -M intel -d ./b | grep -3 printf | grep mov | grep rsi | grep rax > /tmp/a")
  a = open("/tmp/a").read().split("\n")
  if len(a) != 2:
    exit()
  addr = int(a[0].split(":")[0].strip(),16)
  print hex(addr) 

  mm = addr
  os.system("objdump -M intel -d ./b | grep -10 %s | grep '#'> /tmp/a"%(hex(addr)[2:]))
  a = open("/tmp/a").read().split("\n")[1]
  addr = int(a.split(":")[0].strip(),16)
  byte = a.split(":")[1].split("lea")[0].strip()
  print hex(addr)
  byte = byte.replace(" ","")
  print `byte`
  byte = byte.decode('hex')
  val = p32(u32(byte[3:7])+6)
  if chg:
    addrs.append(addr+3)
    vals.append(ord(val[0]))
  else:
    addrs.append(addr+3)
    vals.append(ord(val[0]))
    addrs.append(addr+4)
    vals.append(ord(val[1]))

  os.system("objdump -M intel -d ./b | grep -10 %s | grep mov | grep rdi | grep rax > /tmp/a"%(hex(mm)[2:]))
  addr = int(open("/tmp/a").read().split("\n")[0].split(":")[0].strip(),16)
  print hex(addr)

  addrs.append(addr+2)
  vals.append(0xc6)

  print addrs
  print vals

  for i in range(5):
    s.recvuntil(":")
    s.sendline(hex(addrs[i])+", "+hex(vals[i]))
    
s.interactive()
