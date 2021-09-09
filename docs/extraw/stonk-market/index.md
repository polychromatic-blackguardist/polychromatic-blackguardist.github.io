---
layout: post
tags:
  - WIP
  - extra
  - writeup
  - picoctf
  - reverse-engineering
---

# Stonk Market (WIP)

[Original Challenge *(requires login)*](https://play.picoctf.org/practice/challenge/164)

This is a direct sequel to Stonks, which I've [previously solved](/sjqruaw/stonks/).
In the first one, a `printf` format string vulnerability allowed us to dump the contents of the stack, where the flag was sitting.
This time around, though, the code conveniently reading our flag onto the stack has been cruelly commented out, leaving us with no recourse.

I'm joking, obviously.
Wouldn't be much of a CTF challenge if it was unsolvable, after all.
It *will* be harder, though, because this time we need to properly exploit the binary and get our own code running on there.

In my case, I'm just gonna try to get a simple `system("cat api")`, then `exit(0)` to clean up our tracks.
The way I'm gonna do that is with a [ROP chain](https://en.wikipedia.org/wiki/Return-oriented_programming).
There are far better resources on what they are and how to make them than I could ever write, so for this post, I'll assume you know and gloss over that.

The proximate cause of the vuln is that `printf` doesn't just output data; it can also write data to its parameters, specifically with the long-deprecated `%n` specifier.
`%n` expects its parameter to be an `int*`, where it'll write the number of characters that have been written up to the location of the `%n`.
I'm... not totally sure what it's used for.
I can imagine something like:

```c
struct message {
  int recipient_len;
  int total_len;
  char body[256];
}

struct message result;
snprintf(
  result.body, sizeof(result.body),
  "%s%n%s%n",
  recipient, &result.recipient_len,
  msg_text, &result.total_len
);
```

...but that's an example built around `%n`, not a place where `%n` naturally fits.

Ultimately, it doesn't matter why it was added; what's important is that we can control the _value_ written to it (e.g. with a lot of padding: `%1234d`) and the location to which that value is written (by choosing the index of our `%n` carefully).
The one wrinkle is that we can't write any arbitrary data onto the stack itself:
`%n` looks for a pointer to the location it should write, so we basically get to edit whatever 4 bytes we can find a pointer on the stack to.

So that means we start our exploit development by looking for pointers on the stack.
I actually whipped up a quick, dumb Python script to do that, leaning on the fact that Ghidra says the stack is 0x38 bytes deep:

```py
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
```


