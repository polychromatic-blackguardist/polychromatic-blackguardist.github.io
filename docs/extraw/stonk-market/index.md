---
layout: post
tags:
  - WIP
  - extra
  - writeup
  - picoctf
  - reverse-engineering
title: Stonk Market (WIP)
---

[Original Challenge *(requires login)*](https://play.picoctf.org/practice/challenge/164)

This is a direct sequel to Stonks, which I've [previously solved](/sjqruaw/stonks/).
In the first one, a `printf` format string vulnerability allowed us to dump the contents of the stack, where the flag was sitting.
This time around, though, the code conveniently reading our flag onto the stack has been cruelly commented out, leaving us with no recourse.

I'm joking, obviously.
Wouldn't be much of a CTF challenge if it was unsolvable, after all.
It *will* be harder, though, because this time we need to properly exploit the binary and get our own code running on there.

In my case, I'm just gonna try to get a simple `system("cat api")`, then `exit(0)` to clean up politely.
The way I'm gonna do that is with a [ROP chain](https://en.wikipedia.org/wiki/Return-oriented_programming).
There are far better resources on what they are and how to make them than I could ever write, so for this post, I'll assume you know and gloss over that.

The proximate cause of the vuln is that `printf` doesn't just output data; it can also write data to its parameters, specifically with the long-deprecated `%n` specifier.
`%n` expects its parameter to be an `int*`, where it'll write the number of characters that have been written up to the location of the `%n`.
I'm... not totally sure what it was meant to be used for.
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

Conveniently, we do also control a bit of the stack, so we could conceivably put a pointer on there.
In point of fact, because this executable was compiled with `-no-pie`, we know in advance what all the pointers will be, and can drop a useful one directly on the stack.

So if we put a pointer to the return address on the stack, then we can use `%n` to edit the return pointer to whatever we want, which is the requisite foundation of a ROP chain.

I'm not going to explain in detail how those work; there are far better resources.
What I will explain is what I need, and then the chain I found which supplies it.
I need to:

- Move a chosen value (the command) into `EDI`
- Call `system`
- Move a chosen value (the return value) into `EDI`
- Call `exit`

To find the gadgets I'll use, I'm using Ropper, because I'm used to it.
There are a million and one tools for printing ROP gadgets, and you can use any.

Ropper gave me 13 gadgets which move something to `edi`, but unfortunately, none of them loaded it directly off the stack, and none of the rest move something I can easily control into `edi`.

