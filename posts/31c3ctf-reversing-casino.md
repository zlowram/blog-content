Author: zlowram
Date: 12-30-2014 11:35
Title: 31c3ctf Reversing Casino write-up
Template: post
Comments: enabled


This reversing challenge was really interesting and quite fun. We were given
the source code of a service that was listening on a remote server.

The service was kind of a casino game, in which you had to guess a randomly
generated number, on which you had to place a bet. The mechanics of the game
were simple, if you correctly guessed the number you earned the same amount of
units you bet plus your bet, otherwise you lost your bet units. You had 3
different commands: "account", "flag", and "I bet X and guess Y". The first one
let you check your amount of units, the second one returned a message saying
"No flag for you. play the game!" and the third was the command to play.

```markup
net .alg .bufferedEpollServer "+" via 

sys .file ":-/" via 
/dev/urandom :-/open
6000 :-/read 
" " str .split
txt .consume .u
==random
:-/close

sys .file ":-)" via 
/dev/flag :-)open
200 :-)read
==flag
:-)close

0 ==i 
"go" dump
{ ":" via < 
  "Welcome to the casino. Your commands are: 'account', 'flag', and 'I bet <1234>; and guess <1234>'\n" :write
  i 1 add _ =i
  ==j 
  10 ==k 
  { ==input [
    { input "account\n" eq }
      { "You have " k txt .produce .u " units\n" cat cat :write }
    { input "flag\n" eq }
      { k 1000000 gt { "OK, you won: " flag "\n" cat cat :write } { "No flag for you\nplay the game!\n" :write } ? * } 
    { input "I bet ([0-9]+) and guess ([0-9]+)\n" regex }
      { txt .consume .u ==bet txt .consume .u ==guess
        j 1 add =j
        bet k le {
          k bet sub =k
          j random * _ ==result guess eq
          {   
            k bet 2 mul add =k
            "you were right!\n" :write
          }   
          {   
            "you were wrong the number was " result txt .produce .u "\n" cat cat :write
            k 0 eq { "You lost!\n" :write :finish } rep 
          } ? * 
        } { 
          "you cant bet that much!\n" :write
        } ? * 
        }   
    { 1 } { "I dont understand\n" :write }
  ] conds
  ""  
  } =*in
  { :close } _ =*end =*err
> } +accept
{ 2000 } +port +run
```

The fun part of this challenge was that the server was written in an exotic
programing language. After googling a little bit, we found out that that code
was actually [Elymas](https://github.com/Drahflow/Elymas) code, a stack based programing language. Then we had a
crash course on Elymas so we could understand the code.

After fully understanding the code, we realised that the "flag" command
wouldn't return the flag until we had 1000000 units, so it was clear that we
had to play until we earned that amount, but to do so we should go all-in and
guess correctly 17 numbers in a row. This might seem impossible, but the
generation of the random numbers made them not so random.

To generate the not-so-random numbers, at each execution the service generated
a random number by using an input of 6000 bytes from /dev/urandom. Then, once
it enters in the game loop the not-so-random number appears to be just a
portion of those urandom bytes. The obvious question is, what happens when you
perform more iterations than the number of portions available? The thing is that
Elymas array access, which looks like the snippet below, use the index modulus
the length of the array, so it would go back to the start of the array.

```markup
j random *
```

It was clear, then, that if we played enough guesses in the same connection the
not-so-random number would repeat. But how could we play that many games
without losing all our units? Easy, it was allowed to bet 0 units! With all
this information we wrote a quick ruby script to automatize the game process
and check how many bets we should place in order to make the not-so-random
number repeat.

It turned out that each 125 games the number was repeated, so we adapted the
script to place 125 bets with 0 units, then go all-in with the already
known number, and repeat this process until we earn at least 1000000 units and
get the flag.

The script used to get the flag was the following:

```ruby
#!/usr/bin/env ruby
# by zlowram (@zlowram_)

require 'socket'

s = TCPSocket.new '188.40.18.77', 2000

# We get the greeting from the casino
greeting = s.gets

# We get the "random" number
s.puts "I bet 0 and guess 90\n"
num = s.gets.split(' ').last
puts "The \"random\" number is: " + num 

units = 10
i = 1 
# We bet with 0 and each 125 bets we do a all in :D

while units < 1000000
    if i % 125 == 0
      # Place a winner bet with all the units
      s.puts "I bet " + units.to_s + " and guess " + num.to_s + "\n" 
      s.gets
      # Get the updated units
      s.puts "account\n"
      units = s.gets.split(' ')[2].to_i
      puts "Won! #units: " + units.to_s
    else
      s.puts "I bet 0 and guess 90\n"
      s.gets
    end 
    i = i + 1 
end

# We have now enough credits, ask for the flag!
s.puts "flag\n"
puts s.gets

s.close
```

The last step was to run the script and wait for the flag!

![alt flag](/img/casino_flag.png)

```markup
31C3_033fda2193ec453ed838609c6fdb5aec
```

Greetings to my team [Insanity](http://ka0labs.net)!
