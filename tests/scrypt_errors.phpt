--TEST--
Test scrypt() error conditions
--SKIPIF--
<?php if (!extension_loaded("scrypt")) print "skip"; ?>
--FILE--
<?php

try {
    scrypt("", "", 1, 1, 1, 64);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt("", "", 15, 1, 1, 64);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt("", "", 16, 0, 1, 64);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt("", "", 16, 1, 0, 16);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt("", "", 16, 1, 1, 15);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

try {
    scrypt("", "", 16, 1, 1, PHP_INT_MAX);
} catch (Error $e) {
    echo $e->getMessage() . "\n";
}

?>
--EXPECT--
scrypt(): Argument #3 ($N) must be greater than 1
scrypt(): Argument #3 ($N) must be a power of 2
scrypt(): Argument #4 ($r) must be greater than 0
scrypt(): Argument #5 ($p) must be greater than 0
scrypt(): Argument #6 ($key_length) must be greater than or equal to 16
scrypt(): Argument #6 ($key_length) must be less than or equal to (2^32 - 1) * 32
