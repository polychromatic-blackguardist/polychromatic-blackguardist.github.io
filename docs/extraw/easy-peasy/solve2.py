#!/usr/bin/env python3

import os
import shutil
import sys
import tempfile

from pwn import *

# stolen from the target program
KEY_LEN = 50000


def usage(err=None):
    if err is not None:
        log.failure(f"error: {err}")
    log.failure("usage: one of\n")
    log.failure("  solve.py local <otp.py> <flag file> [key file=rng]\n")
    log.failure("  solve.py remote <host:str> <port:int>\n")
    sys.exit(0 if err is None else -1)


def setup():
    if len(sys.argv) < 2:
        usage("not enough arguments")
    if sys.argv[1] == 'local':
        if not 4 <= len(sys.argv) <= 5:
            usage("wrong number of arguments")
        if any(not os.path.isfile(p) for p in sys.argv[2:]):
            usage("invalid filepath passed")
        otp, flag = sys.argv[2:4]
        with open(flag, 'r') as flag_file:
            flag_data = flag_file.read()
        key = sys.argv[4] if len(sys.argv) == 5 else None
        with tempfile.TemporaryDirectory() as wd:
            tmp_otp = os.path.join(wd, 'otp.py')
            tmp_flag = os.path.join(wd, 'flag')
            tmp_key = os.path.join(wd, 'key')
            shutil.copy(otp, tmp_otp)
            shutil.copy(flag, tmp_flag)

            if key is not None:
                shutil.copy(key, tmp_key)
            else:
                keydata = os.urandom(KEY_LEN)
                with open(tmp_key, 'wb') as tmp_key_file:
                    tmp_key_file.write(keydata)

            solve(process(['python3', tmp_otp], cwd=wd), expected=flag_data)
    elif sys.argv[1] == 'remote':
        if len(sys.argv) != 4:
            usage("wrong number of arguments")
        host, port = sys.argv[2:]
        solve(remote(host, port))
    else:
        usage("unknown connection type")


def solve(cxn, expected=None):
    MAX_FLAG = KEY_LEN
    if expected is not None:
        expected = expected[:MAX_FLAG]
        log.info(f"Solving; expecting flag: {expected!r}")
    else:
        log.info("Solving")

    cxn.recvuntil(b'flag!\n')
    enc_flag = bytes.fromhex(cxn.recvline().decode('utf-8'))

    get_key = log.progress('Retrieving flag key material')
    key_pos = len(enc_flag)
    while key_pos < KEY_LEN:
        get_key.status(f"Key material pointer at {key_pos} / {KEY_LEN}")
        # do it in chunks to stay well clear of the KEY_LEN limit on input
        amt = min(1000, KEY_LEN - key_pos)

        aaaa = b'a' * amt
        cxn.recvuntil(b'encrypt? ')
        cxn.sendline(aaaa)

        key_pos += amt

    get_key.status("Getting initial key material")
    aaaa = b'a' * len(enc_flag)
    cxn.recvuntil(b'encrypt? ')
    cxn.sendline(aaaa)

    cxn.recvuntil(b'go!\n')
    raw_line = cxn.recvline().decode('utf-8')
    enc_aaaa = bytes.fromhex(raw_line)
    if len(enc_aaaa) != len(aaaa):
        log.failure("what the fuck")
    key_mat = bytes(ord('a') ^ b for b in enc_aaaa)

    get_key.success(f'Done (got {len(key_mat)} bytes of key material)')

    # then the first `len(flag)` bytes of the actual key are at the end, since
    # they were used just before our ciphertext by the flag encryption, so
    # grab those (since that's all we care about):
    flag_key = bytes(key_mat[-len(enc_flag):])
    log.info(f"Flag key is {flag_key}")

    flag = bytes(
        enc_flag[i] ^ flag_key[i]
        for i in range(len(enc_flag))
    ).decode('utf-8')

    if expected is not None:
        if flag == expected:
            log.success("Got expected flag!")
        elif flag in expected:
            log.failure(f"Partial flag: {flag!r}")
        else:
            log.failure(f"Mismatched flag: {flag!r}")
    else:
        log.info(f"Got flag: {flag}")


if __name__ == '__main__':
    setup()
