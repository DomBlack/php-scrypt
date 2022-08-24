--TEST--
Test scrypt_pickparams() error conditions
--SKIPIF--
<?php if (!extension_loaded("scrypt")) print "skip"; ?>
--FILE--
<?php

try {
    scrypt_pickparams(-1, 0.75, 1000);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt_pickparams(1024, -1, 1000);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt_pickparams(1024, 0.75, -1);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}
?>
--EXPECT--
scrypt_pickparams(): Argument #1 ($max_memory) must be greater than or equal to 0
scrypt_pickparams(): Argument #2 ($memory_fraction) must be greater than or equal to 0
scrypt_pickparams(): Argument #3 ($max_time) must be greater than or equal to 0
