--TEST--
Test that the scrypt_pickparams() functions works.
--SKIPIF--
<?php if (!extension_loaded("scrypt")) print "skip"; ?>
--INI--
memory_limit=4G
--FILE--
<?php 
echo gettype(scrypt_pickparams(1024, 0.75, 1000));
?>
--EXPECT--
array
