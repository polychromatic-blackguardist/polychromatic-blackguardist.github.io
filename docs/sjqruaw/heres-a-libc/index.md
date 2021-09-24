---
layout: post
tags:
  - WIP
  - sjqr:ua
  - writeup
  - picoctf
  - binary-exploitation
title: Here's a LIBC (WIP)
---

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/179)

This challenge was apparently written by Bernie Sanders; per the description:

![A picture of Bernie Sanders saying the totally real and authentic quote "I am once again asking for you to pwn this binary"](./bernie.jpg "okay maybe it's not actually Sen. Sanders but I can dream")

This challenge comes with an executable and libc, so first things first, I `pwninit`'d it to make sure it could run.
That done, I dove into Ghidra, to find the vulnerability.

It was pretty quick to find; after the welcome message is printed, there's a call to `do_stuff`, which calls this:

```c
__isoc99_scanf("%[^\n]",user_input);
```

A classic buffer overflow, then, because if we provide too much data we'll overflow `user_input`'s space on the stack.
Conveniently, in the Makefile, we can see this was compiled with `-fno-stack-protector`, so there's no need to worry about mitigating stack canaries, and `-fno-pie`, so we can hardcode addresses and not give a darn.
Unfortunately, it _does_ have stack execution prevention enabled, so it won't *quite* be trivial.

Our first step, then, should probably be to get program counter control.
That's easy enough with a bit of experimentation.
Ghidra tells us the buffer is at `Stack[-0x88]`, so let's try that many bytes of padding, eight bytes that'll be our 64-bit pointer soon, and some more data to catch if we come out the other side:

```sh
python -c 'print("a"*0x88 + "b"*0x8 + "c"*0x20)'
```

Pass that in, and we see a segfault, as expected.
Running under GDB, we can see that right at the top of the stack, right where we want em, are our `b`s.
It's not *quite* program counter control, but if you try putting a valid pointer there, you'll see it jump to that address just fine.
For example, put a breakpoint on `getegid`, and insert `000000000040079c` as the pointer data, and you'll see `getegid` get called twice -- once by the real code, once in the ROP.

Now, this ROP is going to be somewhat complex.
There's no 'win function'; we need to launch our own shell.
Luckily that isn't that incredibly difficult, but it means we need to call something like `system`, one of the `exec`s, `popen`, etc.
Those aren't loaded by the program, so they don't have a fixed address, conveniently in the binary already -- but they're still in libc.

Now, we do have the exact libc the target is running, so we at least know the offset `puts` is at, but to turn that into a pointer we can actually use, we need to 
