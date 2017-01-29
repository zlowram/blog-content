Author: zlowram
Date: 12-30-2015 00:09
Title: 32c3ctf Pwn Forth write-up
Template: post
Comments: enabled

For this challenge we are provided with an IP and a port and we are told to connect and get a shell. If we connect, we see the following banner:

```markup
yForth? v0.2  Copyright (C) 2012  Luca Padovani
This program comes with ABSOLUTELY NO WARRANTY.
This is free software, and you are welcome to redistribute it
under certain conditions; see LICENSE for details.
```

It seems it is a known piece of software, so we Google a little bit and we find
out that Forth is an old programming language so the banner is of the yForth
interpreter. As we are told to get a shell, we thought it would be possible to
execute system commands in Forth, so using Google again we find the well-known
site [rosettacode](http://rosettacode.org/wiki/Execute_a_system_command#Forth),
where we can find a huge list of ways to execute system commands in different
languages. In Forth, it happens to be like the folling way:

```markup
s" ls" system
```

This efectively run the "ls" command and we can see that there is a "flag.txt"
file within the current working directory, so we just use the following snippet
to read the file:

```markup
s" cat flag.txt" system
```

Finally, the flag:

```markup
32c3_rooDahPaeR3JaibahYeigoong
```

Greetings to my team [0xb33rs](http://testpurposes.net/)!
