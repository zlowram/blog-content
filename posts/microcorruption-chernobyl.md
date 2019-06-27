Author: zlowram
Date: 06-27-2019 02:08
Title: Microcorruption's Chernobyl write-up
Template: post
Comments: enabled


This is nothing else than another write-up for the Chernobyl level of the Microcorruption challenges. Why do I write this? Easy, I found this challenge pretty interesting and complete so I think it's worth doing the write-up to remind myself how I did it and, in the meantime, if someone else may find this useful that's even better!

So let's get started by reverse engineering all the code to learn how this lock works.

## Reverse Engineering

At a first glance to the disassembly we can quickly spot a function called `run` that has the main loop, so we set this as the starting point.

### Run

First it performs the initialization by creating the hash table structure and then it jumps to the main loop.

The main loop asks for user input to later process it. It will look at the first charecter of the input, taking into account 2 possibilities:

- 'a': Corresponds to the `access` command, which is used to authenticate the user. Syntax: access [username] [pin]
- 'n': Corresponds, most likely, to the `new` command (as only the first letter is checked and the length is 3 chars). Syntax: new [username] [pin]

Then the password is sort of hashed using the code detailed below (already translated to pseudocode)

```python
r10 = 0
r11 = "password"
for i in r11:
  if i != 0x3b:
    r12 = r10
    r12 = r12 * 4
    r12 += r10
    r12 = r12 * 2
    r10 = i
    r10 -= 48
    r10 += r12
```

#### The Hash Table

The reversing of the `create_hash_table` function reveals how that data structure is layed out in memory. It's entirely created within the HEAP, and could be represented as follows:

```markup
+---------------+ 0x0
|       0       |     Number of entries in table
+---------------+ 0x2
|       3       |     Number of bins (2^3)
+---------------+ 0x4
|	      5       |     Max. entries per bin
+---------------+ 0x6
|      ptr      |------------------------------------------->+-----------------------+
+---------------+ 0x8                                        | 0 2 4 6 8 10 12 14 16 | list of ptr
|      ptr      |----------->+---------------------+         +-----------------------+
+---------------+            |       sz: 16        |           | | .. .. .. .. .. ..
                             +---------------------+           | +-- Malloc(90) -- bin 1 (this is where username and password are stored)
                             number of entries per bin         +-- Malloc(90) -- bin 2
```


#### Access

It calls the `get_from_table` function passing the pointer to the hash table, a pointer to the username and a pointer to the "hashed" password. It computes the hash from the username and it computes its modulo against the number of bins in the hash table (initially, 8), which will result in the bin number for that username. Additionally, the number of entries per bin is retrieved in order to iterate within that bin to look for the particular entry. If found it will return the stored "hashed" password, stored in r15 (which is placed 0x10 from the beggining of the bin), otherwise -1.

If the result of the call is -1, it will print a "no such box" message and ask for input again. If the user is found, the password is check to the one that was introduced. Additionally, the high bit is checked in order to know if the user had "privileges" or not. It doesn't make any difference since only a message is printed and nothing lock-related happens.

#### New

The `new` command is meant to create new users on the system. First it does the same as the `access` command, calling the `get_from_table` function to check if the user already exists. If it does, a message will be displayed saying "User already has an account". If it doesn't, it will call the add `add_to_table` function.

The `add_to_table` function receives as parameters a pointer to the hash table, a pointer to the username and a pointer to the "hashed" password. First it will check if the hash table still has some room available, by checking the element count (first element on the hash table structure) against the table capacity (2 to the power of hash_table[1]). If the table is full, the `rehash` function will be called to increase its capacity to make room for the new user that will be added.

Once the `rehash` returns, or even if it wasn't called, then the hash of the username is calculated. Then, it's modulo'ed by the number of bins within the hash table in order to know the destination bin for the new user. Once it has the bin number, it obtains the number of entries that are currently within that bin (hash_table[4] + (bin number * 2)). This number will then be used to compute the exact offset within the destination bin where the username and the 'hashed' will be copied. The username will be at that exact offset, the 'hashed' pin to that offset + 0x10.

#### Rehash function

This probably is the most important function because it's were the `free` function gets called twice, and most likely is where the vulnerability of this binary will reside if the `free` implementation is the same as the "Algiers" challenge, which was vulnerable to the "unlink" method.

This function receives two parameters, one is the hash table pointer and the other the new capacity (number of bins). Basiacally, it does two allocations of the same size as number of bins. Each of them will serve as the list of pointers to bins and the list of number of items in each bin, respectively. Those pointer will be saved in their corresponding fields within the hash table structure, as well as the new capacity. After this, new allocations will be made to create the new bins, whose size will be computed with the following formula: hash_table[2] * 8 + hash_table[2] * 2. Once all is done, the new hash table with the updated capacity is already created. Now it will loop through the old bins and copy the entries to the new table by calling the `add_to_table` function.

Then, the remaining step is to free the old bins and the old lists. To do so, it will iterate first throught the old list of bins, freeing each entry. Then it will just free the list of pointers to bins and the list of number of elements per bin.


### The HEAP

Let's do now a recap of how the HEAP worked:

#### Chunk

```markup
+----+----+--------------------+------+
| BK | FW | SZ (with used bit) | DATA |
+----+----+--------------------+------+
```

BK: Backwards pointer to previous chunk
FW: Forward pointer to next chunk
SZ: Size of current block with LSB indicating if used or not (the size saved here is requested size * 2)

#### Free

The Free function can be written in C as follows:

```markup
struct chunk_header_struct {
  uint16 bk;
  uint16 fw;
  unit16 sz;
} chunk_header;


uint16 current_chunk = (chunk_header *)(r15 - 0x6); // r15 contains the offset to be freed
current_chunk->sz &= 0xfffe; // unsetting the used bit

/* Coalesce with previous chunk if not in use */
if (current_chunk->bk->sz & 0x1) {
  current_chunk->bk->sz += 0x6;
  current_chunk->bk->sz += current_chunk->sz;
  current_chunk->bk->fw = current_chunk->fw; // <-- Vulnerable here
  current_chunk->fw->bk = current_chunk->bk; // <-- Also vulnerable here
  current_chunk = current_chunk->bk;
}

/* Coalesce with next chunk if not in use */
if (current_chunk->fw->sz & 0x1) { // Coalesce with next chunk if not in use
  current_chunk->fw->sz += current_chunk->sz;
  current_chunk->fw->sz += 6;
  current_chunk->fw = current_chunk->fw->fw;
  current_chunk->fw->bk = current_chunk;
}
```

The Free function is vulnerable to the "unlink" method. That is, if we are able to manipulate the chunk metadata we will have the ability to write an arbitrary 2 byte value to any arbitrary offset (write-what-where primitive). The following two diagrams show how the data should be replaced within the chunk metadata to successfuly achieve the write-what-where primitive:

```markup
+------------------------------+
| WHERE-0x2 | WHAT | SZ | DATA |
+------------------------------+

+--------------------------+
| WHAT | WHERE | SZ | DATA |
+--------------------------+
```


## Exploiting it

### The strategy

With all the knowledge we have acquired we're now able to define an exploit strategy. The vulnerability resides in the Free function for the current heap implementation (as seen in the Algiers level) so we will need to be able to overwrite, somehow, the chunk headers.

This becomes easy since we fully know when and why the chunks are freed. Now we need to know how to overwrite the chunk metadata. Overflowing a bin is possible due to the fact that you can fit more username-pin pairs in a bin than its size. We can force this by generating enough collisions on the hash function. A bin fits 5 username-pin pairs, but a call to the rehash function won't happen until the hash table have 12 elements. If we manage to store a 6th username-pin pair it will directly overwrite the next chunk's header.

Leveraging this should allow us to write a reliable payload to trigger the write-what-where primitive when the bin is freed.

### Creating collisions

We need to consistently trigger hash colisions to be able to place users in the same bin. Since we will need to actually create those users for the exploit, let's code the hashing algorithm in order to generate usernames that will end up in the same bin.

```python
#!/usr/bin/env python

import sys

def hash(username):
    r14 = username
    r15 = 0
    for i in r14:
      r13 = ord(i)
      r13 += r15
      r15 = r13
      r15 = (r15 << 5) & 0xffff
      r15 = (r15 - r13) & 0xffff
      r15 = r15 % 8
    return r15

for i in range(0,100):
    result = hash(str(i))
    if result == 0:
        print "Username: {}, Bin: {}".format(i, result)
```

### The payload

The following diagram pictures how the overflow of the bins look like:

```markup
         BIN 1        |        BIN 2
+-------------------------------------------+
| BK | FW | SZ | DATA | BK | FW | SZ | DATA |
+-------------------------------------------+
               ^-- overflow          ^ Free
```

As we already said before, we need to fit enough users within Bin 1 so it overflows into Bin 2. However, after playing around with the payload I suddenly realized that we can't just overwrite the chunk metadata of any bin because the `rehash` function calls `malloc` before freeing, and was causing the program to stop due to Heap Exhaustion.

The thing is that the malloc implementation traverses all the list of chunks looking for a chunk not in use of a particular size. It knows it had traversed all the heap when the FW pointer points to an address lower than the one of the first chunk.

Yep, you got it right, if we overwrite the BK and FW pointers of the chunk we want to use for the `unlink` exploit, it will make malloc think that the heap is already exhausted.

In order to fix this, we need to manipulate the actual list of chunks in order to allow malloc to walk over the overwritten chunk that will trigger the write-what-where primitve. How can we do that? By overwriting the FW pointer of the previous chunk and make it point to the next chunk, leaving out from the heap the chunk that will hold the actual payload.

Now we might think that we got it, and that we just need to fill the first bin to overwrite the second one in order to remove the third one from the HEAP. Then the question is, how we can modify the chunk metadata of the third bin? The first answer is overflowing the second bin, but that requries more than 11 new users... and yep, the 12th user will trigger the rehash already without having overwritten that data!

But wait, what if we keep filling the first bin after overwriting the first one? Yep, you got it right again, you can overwrite chunk 3 metadata with the username of the 11th user. Then we just need to add another dummy user to trigger the rehash method and get the program to free our manipulated chunk that actually contains the payload.

Taking into account everything we know now, we should be able to write a script that does the following:

1. Create 5 users that fall within the same bin, let's say bin 1, so the 6th user will actually overwrite the next chunk metadata.
2. Create a user whose username contains the metadata to overwrite (FW pointer to next-next chunk) and make sure it will fall into the same bin as the previous 5 users.
3. Create 4 more users that fall within the same bin as the other users we created. The 5th user will overwrite the next (of the next) chunk metadata. This overwritten chunk will hold the actual payload that will be triggered when the program frees that specific chunk.
4. Create an additional user that will be the 12th user and will trigger the rehash function. It doesn't matter which bin it will the user be saved in.

It is important to note that we will leverage this last user to include our shellcode in, since the input for that command will not be processed before the call to the rehash function, so we will be able to use shellcode with nullbytes.

Basically, we will use the write-what-where primitive to overwrite a RET address within memory and redirect the execution flow to our stored shellcode.

This post is already huge, so I will skip the script and directly include the final payload:

```markup
6e6577203720313233343b6e657720313020313233343b6e657720313820313233343b6e657720323120313233343b6e657720323920313233343b6e6577201234bc5151127720313233343b6e657720333220313233343b6e657720343320313233343b6e657720353420313233343b6e657720363520313233343b6e657720414141414141843eea3d51696c20313233343b6e65772041023c78403041324000ffb01210002031323334
```
