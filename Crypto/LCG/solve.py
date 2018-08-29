#!/usr/bin/python

from pwn import *
from fractions import gcd
from Crypto.Util.number import *
import time

p = s=remote("lcg.eatpwnnosleep.com",12345)
a = []
for i in range(16):
  p.sendline("1")
  a.append(int(p.recvuntil("\n")[:-1]))

print a

for_x=[]
for_y=[]
for i in range(12):
  for_x.append(( (a[i+2]-a[i+1])*(a[i+3]-a[i+2])-(a[i+1]-a[i])*(a[i+4]-a[i+3]),(a[i+2]-a[i+1])**2-(a[i+1]-a[i])*(a[i+3]-a[i+2])))
  for_y.append(( (a[i+3]-a[i+2])*(a[i+3]-a[i+2])-(a[i+4]-a[i+3])*(a[i+2]-a[i+1]),(a[i+1]-a[i])*(a[i+3]-a[i+2])-(a[i+2]-a[i+1])**2))


#b=a
#b.sort()

#print for_x
#print for_y

for_m = []
for i in range(11):
  aaaa,bbbb = for_x[i+0]
  cccc,dddd = for_x[i+1]
  if aaaa*dddd>cccc*bbbb:
    for_m.append(aaaa*dddd-cccc*bbbb)
  else:
    for_m.append(cccc*bbbb-aaaa*dddd)
#print for_m
_gcd = for_m[10]
for i in range(11):
  _gcd = gcd(_gcd, for_m[i])
#print hex(_gcd)

if _gcd > 0xffffffffffffffff:
  print "FAIL"
  exit()
#if not isPrime(_gcd):
#  print "FAIL2"
#  exit()

print "GOOD"

for i in range(12):
  aaaa, bbbb = for_x[i]
  aaaa %= _gcd
  bbbb %= _gcd
  tmp = (inverse(bbbb,_gcd)*aaaa)%_gcd
  print tmp

print "#"*50
x = tmp
for i in range(12):
  aaaa, bbbb = for_y[i]
  aaaa %= _gcd
  bbbb %= _gcd
  tmp = (inverse(bbbb,_gcd)*aaaa)%_gcd
  #print tmp
y = tmp

print "#"*50
#print z

#print x
#print y
#print m
print a
f1 = (x*a[1]+y*a[0])%_gcd
print f1
f2 = a[2]
print f2
z = (f2-f1)%_gcd
#print a[2]
print z
#print info
answer = []
for i in range(16):
  answer.append((x*a[15+i]+y*a[14+i]+z)%_gcd)
  a.append(answer[i])

for i in answer:
  print str(i)
  p.sendline(str(i))
  time.sleep(0.5)

p.interactive()
