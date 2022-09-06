--TEST--
Test if senstive parameters are not shown in the stacktrace
--SKIPIF--
<?php
if (!extension_loaded("scrypt")) print "skip";
if (PHP_VERSION_ID < 80200) print "skip Test requires PHP 8.2.0+";
?>
--FILE--
<?php
scrypt("password", "salt", 1, 1, 1, 64);
?>
--EXPECTF--
Fatal error: Uncaught Error: scrypt(): Argument #3 ($N) must be greater than 1 in %s:%d
Stack trace:
#0 %s(%d): scrypt(Object(SensitiveParameterValue), Object(SensitiveParameterValue), 1, 1, 1, 64)
#1 {main}
  thrown in %s on line %d
