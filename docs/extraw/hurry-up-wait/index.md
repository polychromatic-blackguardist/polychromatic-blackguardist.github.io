---
layout: post
tags:
  - extra
  - writeup
  - picoctf
  - reverse-engineering
title: Hurry up! Wait!
---

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/165)

This is a reverse-engineering challenge, and an interesting one.
As usual, my first step was to pop it into Ghidra, and I was immediately intrigued when I saw this in `main`:

```c
undefined4 main(int argc,char **argv,char **envp)
{
  undefined local_10 [8];
  
  gnat_envp = envp;
  gnat_argv = argv;
  gnat_argc = argc;
  __gnat_initialize(local_10);
  FUN_00101d7c();
  FUN_0010298a();
  FUN_00101d52();
  __gnat_finalize();
  return gnat_exit_status;
}
```

Now, that's *fascinating*.
GNAT, for those who don't know, is the **GN**U **A**da **T**oolkit, so this is an Ada binary.
Oddly named, considering it's a Linux executable, but oh well.
So diving into the first unnamed function, we see... something.
A whole pile of random `ada__` and `system__` and `__gl` function calls and variables set, all of which looks like 'backend' stuff.
Probably initialization, so let's ignore it.
The last unnamed function, at a quick check, is the opposite; it runs some teardown.

So the function in the middle has to be the meat of the challenge, and opening it, it's intimidating at first:

```c
void FUN_0010298a(void)
{
  ada__calendar__delays__delay_for(1000000000000000);
  FUN_00102616();
  FUN_001024aa();
  FUN_00102372();
  FUN_001025e2();
  FUN_00102852();
  FUN_00102886();
  FUN_001028ba();
  FUN_00102922();
  FUN_001023a6();
  FUN_00102136();
  FUN_00102206();
  FUN_0010230a();
  FUN_00102206();
  FUN_0010257a();
  FUN_001028ee();
  FUN_0010240e();
  FUN_001026e6();
  FUN_00102782();
  FUN_001028ee();
  FUN_00102102();
  FUN_001023da();
  FUN_0010226e();
  FUN_001021d2();
  FUN_00102372();
  FUN_001023a6();
  FUN_001021d2();
  FUN_00102956();
  return;
}
```

The challenge name, "Hurry up! Wait!" is pretty clearly because of the `delay_for` call at the top, but luckily we can just ignore that and reverse the rest of the file.
The first unnamed function is shorter, but no less odd, at first:

```c
void FUN_00102616(void)
{
  ada__text_io__put__4(&DAT_00102cd8,&DAT_00102cb8);
  return;
}
```

Still, nothing to do but poke.
So we double-click on the first `DAT_`, and to me the nature of the challenge became immediately obvious.
See, `DAT_00102cd8` is just the character `p`.
`ada__text_io__put__4` takes a one-byte first parameter in `AL`.
And most interestingly, all around `DAT_00102cd8` are the rest of the alphabet, plus a few fun extra characters like `C`, `T`, `F`, `_`, `{`, and `}`.
So, at a guess, every function is going to write a character to output, and the challenge will be reversing each function to get which character it outputs.

After retyping the characters as `char`s and confirming that `DAT_00102cb8`, the second parameter, is the file descriptor `1`, aka stdout, I looked at the second function:

```c
void FUN_001024aa(void)
{
  ada__text_io__put__4(&CHAR_i_00102cd1,&stdout);
  return;
}
```

...hm.
Okay, maybe this challenge is gonna be easier than expected.
Every function turns out to follow the same pattern, just writing a single character to stdout.
After renaming them all accordingly, we have:

```c
void FUN_0010298a(void)
{
  ada__calendar__delays__delay_for(1000000000000000);
  put_p();
  put_i();
  put_c();
  put_o();
  put_C();
  put_T();
  put_F();
  put_{();
  put_d();
  put_1();
  put_5();
  put_a();
  put_5();
  put_m();
  put__();
  put_f();
  put_t();
  put_w();
  put__();
  put_0();
  put_e();
  put_7();
  put_4();
  put_c();
  put_d();
  put_4();
  put_}();
  return;
}
```

A little bit of multi-cursor text editing to assemble the single characters into one flag, and we have our final result.

All told, a surprisingly easy challenge, but one I wanted to write up because Ada is cool.

This could also have been done as a Ghidra script, but it'd have taken me longer to write the script than it did to just manually go through each function and rename them, especially because there were a bunch of duplicates.
