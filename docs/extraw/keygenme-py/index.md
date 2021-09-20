---
layout: post
tags:
  - extra
  - writeup
  - picoctf
  - reverse-engineering
title: keygenme-py
---

[Original challenge *(requires login)*](https://play.picoctf.org/practice/challenge/121)

keygenme-py is a simple reverse-engineering challenge.
The challenge file is a little Python script, implementing a pretty standard first-year astrology project, a mana burn calculator for astral projection, and a more complex calculation for astral slingshot approach vectors.
The actual challenge is finding the license key, which is fairly simple.
There's a function, `check_key`, which implements the key check we'll need to reverse.
You could also try breaking Fernet, but that seems harder.

The key check is very simple, though it's verbose.
First it makes sure the key starts with a fixed starting string.
Then it hashes the username, and checks each subsequent character of the entered key against a hardcoded index of the demo's username's hash.
Because we have the demo username, we can easily just... hash it ourselves, then extra those indices:

```py
import hashlib

part1 = "picoCTF{1n_7h3_|<3y_of_"

# part2 calculated dynamically from:
username = b"SCHOFIELD"
hash_idxs = [4, 5, 3, 6, 2, 7, 1, 8]
username_hash = hashlib.sha256(username).hexdigest()

part3 = "}"

print(part1, end='')
for idx in hash_idxs:
    print(username_hash[idx], end='')
print('}')
```

That'll print out our flag.
