---
layout: post
tags:
  - extra
  - writeup
  - picoctf
  - reverse-engineering
title: not crypto
---

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/222)

## Reverse-engineering

As with most RE challenges, my first move was to pop this into Ghidra.
When I did, I saw a main function with a few pages of gibberish.
After squinting a little closer, I cursed at my monitor and realized I was looking at AES.
To confirm, I looked at the first global referenced, and yup, there's [Rjindael's forward S-box](https://en.wikipedia.org/wiki/Rijndael_S-box#Forward_S-box).
Now, there's no key being entered, so that means it has to be hardcoded in there somewhere.
But hold on -- before we dive down that rabbit hole, let's look at the challenge description:

> there's crypto in here but the challenge is not crypto... 🤔

That implied to me that the challenge was some kind of binary exploitation, despite the category of the challenge, so I looked for user input.
It was a bit hidden, but after a quick bout with GDB I found:

```c
fread(user_input,1,0x40,stdin);
```

I then looked for every usage of that variable, and I only found a single one:

```c
iVar24 = memcmp(memcmp1,user_input,0x40);
if (iVar24 == 0) {
  puts("Yep, that\'s it!");
}
else {
  iVar24 = 1;
  puts("Nope, come back later");
}
```

...hm.
Interesting.
So it seems like all that mess of crypto is just to calculate the thing our user input will be compared against -- remember, this is the *only* use of our user input.
It's also the only `memcmp` call, so I ran it under GDB again:

```
$ gdb ./not-crypto
[the usual spiel]
> b memcmp
Breakpoint 1 at 0x1060
> r
Starting program: /home/e211fde5/picoctf/not-crypto/not-crypto 
I heard you wanted to bargain for a flag... whatcha got?
[I typed 64 a's]
```

Then a breakpoint was hit.
`memcmp` takes parameters in `rsi` and `rdi`, but I didn't even need to know that, because just at a glance at the registers I saw this:

```
$rdi   : 0x00007fffffffe070  →  "picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1[...]"
```

Well, well, well, that's interesting.

```
> x/s $rdi
0x7fffffffe070:	"picoCTF{c0mp1l3r_0pt1m1z4t10n_15_pur3_w1z4rdry_but_n0_pr0bl3m?}\n\326\340\377\377\377\177"
```

And there's our flag.
