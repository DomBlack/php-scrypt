--TEST--
Test that the scrypt_pickparams() functions works.
--SKIPIF--
<?php if (!extension_loaded("scrypt")) print "skip"; ?>
--INI--
memory_limit=2G
--FILE--
<?php 
echo gettype(scrypt_pickparams(0, 0.75, 0));
?>
--EXPECT--
array
