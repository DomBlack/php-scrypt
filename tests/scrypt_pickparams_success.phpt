--TEST--
Test that the scrypt_pickparams() functions works.
--SKIPIF--
<?php if (!extension_loaded("scrypt")) print "skip"; ?>
--FILE--
<?php

$params = scrypt_pickparams(1024, 0.75, 1000);

echo gettype($params) . "\n";
echo gettype($params["n"]) . "\n";
echo gettype($params["r"]) . "\n";
echo gettype($params["p"]) . "\n";

?>
--EXPECT--
array
integer
integer
integer
