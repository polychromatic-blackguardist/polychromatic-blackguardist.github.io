---
layout: post
tags:
  - extra
  - writeup
  - picoctf
  - cryptography
---

# Easy Peasy

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/125)

As the description says, a one-time pad is completely unbreakable...
at least, if used properly.
In general, OTPs are only as secure as the key material; if it's not completely cryptographically secure randomness that's never been used before, it's no longer unbreakable.
In particular, key material reuse usually leads to the OTP being vulnerable to chosen plaintext attacks.
(In general, though, don't use an OTP.
They have perfect security, but they require a completely random key as long as the plaintext -- and if you have the ability to send that securely to the recipient, *just send the text securely over that method instead*.)

In this case, we have a XOR-based OTP, which only uses at most 50,000 bytes of key material, before restarting.
That's unfortunate, because we can just feed it 50,000 bytes of known plaintext, then XOR the ciphered result with our plaintext to get back out the entire key material.
Then we just XOR that key material with the flag, and... we have the flag.

The name's accurate; if you know a thing or two about one-time pads this *is* easy peasy.

My [solve script](./solve.py) can run against both local and remote targets, as usual.

> **Note**:
> The PicoCTF servers are currently serving a defective `otp.py` which *does not* behave the same as the provided one, and accordingly the challenge is 'unsolvable'.
> (It can actually be worked around, but that's not really a fair part of the challenge, so I'm not including it here.)
