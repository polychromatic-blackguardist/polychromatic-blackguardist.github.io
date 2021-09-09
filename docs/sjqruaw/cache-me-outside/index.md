# WORK IN PROGRESS

## Cache Me Outside

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/146)

This challenge came as a binary, rather than a source file.
Running it with `-h` and `--help` didn't do anything obvious; it just spun for a minute then segfaulted, so I opened the binary in Ghidra.
It doesn't look *that* good, but with a bit of massaging, the overall program flow becomes clear:

- Read `0x40` bytes from `flag.txt` into a stack array, `flag`
- `malloc` 7 copies of the target data, `"Congrats! Your flag is: [flag]"`
- `malloc` a bad buffer with `Sorry! This won't help you: [some random data]"`
- `free` the last of the 7 copies
- `free` the bad buffer
- Allow the user to edit a single byte, relative to the first target
- `malloc` another buffer, then print the uninitialized data inside

All of the `malloc`s are the same size, `0x80` bytes.

### Running heapedit

Now, interestingly, it doesn't seem like it's supposed to segfault, because the one on the server doesn't.
It obviously has bad memory hygiene, but something in my local copy is out-and-out *broken*, in a way it took me a while to figure out.
According to GDB, it's dying in `__libc_start_main`; it doesn't even get to the actual code.
The problem, as far as I can tell, is some kind of fundamental mismatch between my system and the binary, but PicoCTF provided the correct `libc`, and that's the only dependency -- except for the linker.
Now, there's [a tool](https://github.com/io12/pwninit) which will figure out the linker for you, and at least as of September 2, 2021 it doesn't seem to be malicious.

Once you've run `pwninit`, you can run `heapedit` with `./ld-2.27.so ./heapedit`, and it'll work fine.

You can also, if you want, manually hunt down `ld-2.27` and grab the `.so` yourself; that's all that pwninit does that we care about.
Fair warning, though, it's a huge pain to do.

Once you have everything, you can either:

- Run the binary as `./ld-2.27.so ./heapedit`
- Patch the elf with `patchelf --set-interpreter ./ld-2.27.so ./heapedit`, then run it normally as `./heapedit`

I did the latter.
It makes running with GDB easier.

### Explaining heapedit

So the attack we're meant to use is pretty clear:
Corrupt a heap data structure, with our one permitted byte, such that the last `malloc` will sit in the same spot as one of the target buffers.
Conveniently, a copy of the `libc` they're using has been included, so we can pull that open in Ghidra too, and look at its heap manager.
Unlike `heapedit`, though, `libc` will take a hot minute to analyze.
Get some coffee.
Or, for a bit of coding fun, write a script to brute-force it **against a copy running locally**.
(Don't be a dick to PicoCTF's servers.)

Technically, because this binary isn't (as far as I can tell) relocated, you could *probably* also find the relevant pointers on the stack and edit them to print the flag, but I'm going to do this the intended way.
That means we need to dig into how the heap works!

There is a *lot* of complexity to glibc's heap manager.
At the most basic level, it's fairly simple:
`malloc` will return a pointer to some free space, of the requested size.
Just *before* that pointer, there's a few bytes (in this case, 16) of metadata, including the flags and size.
Theoretically, that's all the information `malloc` needs; whenever it wants more space it can just scroll through the heap area until it finds an open space.
In practice, that's *incredibly slow*, so there have been optimizations over the years.
One of the most important for multithreaded code is the Tcache, the thread-local chunk cache, which keeps a few chunks of commonly allocated sizes around in thread-local storage *without* releasing them to the global allocator, so the next time the thread requests a chunk of that size it doesn't need to worry at all about thread safety.

Unfortunately, the Tcache is also what breaks the easiest solution.
Without it, we could simply set the `free`d bad chunk to "in use", taking advantage of the fact that sequentially allocated chunks are located next to each other in memory to figure out the index
Because of the Tcache, though, the two `free`d chunks are stored on a special list, and we can't get them off it just by changing the flags -- they're *already marked* as "in use" to the global allocator, since we don't want other threads allocating them out from under us.

The Tcache also breaks the second-easiest way.
We could theoretically just edit the size, so even though it's considered 'free' it isn't big enough to hold the 0x80 bytes that are requested.
Unfortunately, though, Tcache bins store the size with the bin itself, so even though the chunk says it's `0x30` bytes long, it'll still get provided when the Tcache is asked for a `0x80`-byte chunk.

### Investigating heapedit

So we instead have to find and edit the Tcache.
Luckily, Tcache data is itself stored on the heap, which means we should be able to index off the first target malloc to get to it.
The exact values will vary by `libc` version -- even with compatible ABIs; this is very much part of the Deep Lore and is *not* stable -- but conveniently, we've been given the precise libc the target is running.

At this point, we *finally* get into actually dynamically analyzing the binary.
I'm using [`gef`](https://github.com/hugsy/gef/) to tell me about the heap, but anything which can tell you the locations of all the allocated chunks and the chunks in the Tcache will do just fine.

First, let's look at what's in the Tcache:

```
gef➤  heap bins
─────────────────────────── Tcachebins for thread 1 ───────────────────────────
Tcachebins[idx=7, size=0x90] count=2  ←  Chunk(addr=0x603890, size=0x90, flags=PREV_INUSE)  ←  Chunk(addr=0x603800, size=0x90, flags=PREV_INUSE)
─────────────────────────── Extra stuff was omitted ───────────────────────────
```

Alright, so we should probably see something saying the size is `0x90`, and the addresses `0x603890` and `0x603800` should be mentioned, too.
Yes, `0x90`; actually, `0x91` is what we'll be looking for in memory.
I'm not sure why the size is `0x11` bytes larger in memory than the logical size of the chunk.
`0x10` would make sense, as that's the size of the metadata, but the one extra byte is... odd.
It doesn't really matter for this exploit, though.

The Tcache data is stored on the heap, so let's see the chunks we'll need to examine:

```
gef➤  heap chunks
Chunk(addr=0x602010, size=0x250, flags=PREV_INUSE)
    [0x0000000000602010     00 00 00 00 00 00 00 02 00 00 00 00 00 00 00 00    ................]
Chunk(addr=0x602260, size=0x230, flags=PREV_INUSE)
    [0x0000000000602260     98 24 ad fb 00 00 00 00 90 24 60 00 00 00 00 00    .$.......$`.....]
Chunk(addr=0x602490, size=0x1010, flags=PREV_INUSE)
    [0x0000000000602490     74 68 69 73 20 69 73 20 61 20 74 65 73 74 20 66    this is a test f]
(then there's the 8 which heapedit allocates...)
Chunk(addr=0x603920, size=0x410, flags=PREV_INUSE)
    [0x0000000000603920     31 0a 00 00 00 00 00 00 00 00 00 00 00 00 00 00    1...............]
```

Well, that's a lot, but there's really no way around examining them all to see which is correct.
We can do that with `x/[num]w [address]`, which prints `num` 4-byte words starting at `address`.
That'll make it easier to see the pointers.

Let's start with the first.
Note that `size` is in hex bytes, and we need decimal words.
I just used my shell; run `echo $(( 0x250 / 4 ))` on any modern shell and it should work.

