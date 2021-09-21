---
layout: post
tags:
  - sjqr:ua
  - writeup
  - picoctf
  - binary-exploitation
title: Here's a LIBC
---

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/179)

This challenge was apparently written by Bernie Sanders; per the description:

![A picture of Bernie Sanders saying the totally real and authentic quote "I am once again asking for you to pwn this binary"](./bernie.jpg "okay maybe it's not actually Bernie but I can dream")

This challenge comes with an executable and libc, so first things first, I `pwninit`'d it to make sure it could run.
That done, I dove into Ghidra, to find the vulnerability.

It was pretty quick to find; after the welcome message is printed, there's a call to `do_stuff`, which calls this:

```c
__isoc99_scanf("%[^\n]",user_input);
```

A classic buffer overflow, then, because if we provide too much data we'll overflow `user_input`'s space on the stack.
Conveniently, in the Makefile, we can see this was compiled with `-fno-stack-protector`, so there's no need to worry about mitigating stack canaries.


