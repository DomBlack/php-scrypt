PHP scrypt module
=================

[![Build Status](https://travis-ci.org/DomBlack/php-scrypt.svg?branch=master)](https://travis-ci.org/DomBlack/php-scrypt)

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

----

PECL Install
============

This extension is now avaible through PECL.

```
pecl install scrypt
```

Build From Source
=================

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

Using Visual Studio 2008 (or Visual C++ Express 2008) open up the attached project
inside the VS2008 folder. This project assumes you have the PHP thread safe source at;
`C:\phpsrcts\`, a PHP install at `C:\php\` and this source code extracted to
`C:\php-scrypt\`.

1. Build the project.
2. Copy the resultant `scrypt.dll` to your ext directory in PHP.
3. Add the extension to your php.ini

````
    ; Enable scrypt extension module
    extension=scrypt.dll
````

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
