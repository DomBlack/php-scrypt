PHP scrypt module
=================

This is a PHP library providing a wrapper to [Colin Percival's scrypt implementation](http://www.tarsnap.com/scrypt.html). Scrypt is a key derivation function designed to be far more secure against hardware brute-force attacks than alternative functions such as PBKDF2 or bcrypt.

Details of the scrypt key derivation function are given in a paper by Colin Percival, Stronger Key Derivation via Sequential Memory-Hard Functions: [PDF](http://www.tarsnap.com/scrypt/scrypt-slides.pdf).

An example class using this module can be found in; scrypt.php

Join in!
--------

We are happy to receive bug reports, fixes, documentation enhancements, and other improvements.

Please report bugs via the [github issue tracker](http://github.com/DomBlack/php-scrypt/issues).

Master [git repository](https://github.com/DomBlack/php-scrypt):

    git clone git://github.com/DomBlack/php-scrypt.git

Authors
-------

This library is written and maintained by Dominic Black, <thephenix@gmail.com>.

Build Command
=============

Unix/OSX
--------

1. `phpize`
2. If on OSX; `export CFLAGS='-arch i386 -arch x86_64'`
3. `./configure --enable-scrypt`
4. `make`
5. `make install`
6. Add the extension to your php.ini

````
    ; Enable scrypt extension module
    extension=scrypt.so
````

Windows
-------

I have written a config.w32, however it is untested.

Legal Stuff
===========
This works is licensed under the BSD 2-Clause license.

Original Scrypt Implementation;
 Copyright (c) 2009 Colin Percival

PHP Module;
 Copyright (c) 2012, Dominic Black

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.