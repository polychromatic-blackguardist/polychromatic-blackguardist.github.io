---
layout: post
tags:
  - WIP
  - extra
  - writeup
  - csaw
  - binary-exploitation
---

# haySTACK (WIP)

[Original challenge *(requires login; may be expired)*](https://ctf.csaw.io/challenges#haySTACK-29)

To quote their site, with a bit of added emphasis, CSAW is

> [d]esigned as an entry-level, jeopardy-style CTF, this competition is for students who are trying to break into the field of security, as well as for advanced students and **industry professionals who want to practice their skills**. 

Well, well, well, if that isn't me to a T.
So I 'competed' with a few coworkers, and we did alright -- mostly, we wanted to practice binary exploitation, and while I broke a couple of web challenges, they weren't really the point.

haySTACK was a fairly simple challenge.
The name implied to me that it'd be a stack overflow of some kind.
Popping it open in Ghidra, we see... a bit of a mess.
As it turns out, there's a _tremendously_ huge array allocated on the stack, which is how I learned that there's an upper size limit to Ghidra's stack analysis.
Still, it's not too hard to read once you poke at the assembly a little and see something like this:

![TODO: image]()

That massive buffer is initialized as an `int` array, with each value being `0xb00`, then one value is randomly selected and has the value `1337` written to it.
Our goal is to find that `1337` in the sea of `0xb00`s.
Given the size of the buffer, we're not gonna be able to blindly guess the index, so there has to be a trick somewhere.

There's only one point where we have input, and I spent a while trying to figure out how we could possibly overflow the stack with it.
What was odd was I was getting interesting results -- any value 'in range' got me the expected `0xb00`, but very large values got me very different results.
That got me looking at the `atoi` docs, to see if there was anything exploitable in the documented behavior, then the implementation in my libc, and it all looked rock-solid; no way to overflow any buffers.
And yet I was still getting odd results with very large numbers, so *something* was happening.

I spent a while puzzling that out.
Eventually, it hit me, like a large trout to the face.
*`atoi` does negative numbers too.*
That's a pretty obvious method to do a buffer overflow, and it's not checked; the result of `atoi` is only checked if it's too *large*, and there's no check for negative results.

Conveniently, there's something under the giant buffer on the stack:
The number of the target buffer.
That offset from the haystacks is fixed, so we can enter it, and get the haystack number in hex.
Convert that to decimal, and we get the answer we need to enter.

You *could* do the requisite math to figure out what the offset is, but that would have taken a lot of manual effort, and it only took like five minutes to write [a Python script](./search.py) that tried every negative number from -1 to -1000 and printed the first that returned the target number, as checked by looking for the success message.
Once I had the offset, solving the challenge manually was trivial:
Enter the offset, convert the result from hex, enter that, victory.

## Option 2: Predicting Randomness

There was another solution, which I didn't use (or even notice) but it's so clever I wanted to mention it.
The random index is generated with `rand`, which is seeded just beforehand with `srand(time(NULL))`.
The server uses more-or-less accurate UTC, so you can just make sure your computer is synced as well, then `srand(time(NULL)); rand()` on your own machine to get the same number.
You might need to try a couple of times to get it just right, but your code would look something like this:

```c
time_t now = time(NULL);
int cxn_sock = connect();

srand(now - 1);
try_code(cxn_sock, rand());

srand(now);
try_code(cxn_sock, rand());

srand(now + 1);
try_code(cxn_sock, rand());
```

(Note that the time is gotten when the connection is open, and one connection is used -- the program `srand(time(NULL))`s when it starts, so you want to make sure your `srand`s are based on approximately the same time.)

Given the name, I think the buffer overflow is the intended solution, but this is still a very cool one.
