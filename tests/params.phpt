--TEST--
Test that the scrypt_pickparams() functions works.
--SKIPIF--
<?php if (!extension_loaded("scrypt")) print "skip"; ?>
--FILE--
<?php 
echo scrypt_pickparams(1024, 0.75, 1000);
?>
--EXPECT--
Array