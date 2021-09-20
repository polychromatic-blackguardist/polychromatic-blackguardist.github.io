---
layout: post
tags:
  - extra
  - writeup
  - picoctf
  - cryptography
title: Easy Peasy
---

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
> The PicoCTF servers are currently serving a defective version of the challenge.
> TL;DR: The `key` file is the wrong size, due to an error in generation, so incorrect key data is being used to OTP things.
> The bug's been reported, it should be fixed soon.
> Depending on how exactly you 'phrased' your solution it might not be an issue, but if you try to do like I did and grab *all* the key data, then grab from that the key data used for the flag, it won't work properly.
> A currently functional solve script is available [here](./solve2.py), which feeds enough data to advance the key material position back to the beginning, retrieves exactly enough bytes, and does the same XOR trick to get the key material, then the flag.