PHP_ARG_ENABLE(scrypt, whether to enable scrypt support,
[ --enable-scrypt  Enable scrypt support])

PHP_ARG_ENABLE(scrypt-debug, whether to enable scrypt debug messages,
[ --enable-scrypt-debug  Enable scrypt debug messages])

if test $PHP_SCRYPT != "no"; then
    if test $PHP_SCRYPT_DEBUG != "no"; then
        AC_DEFINE(SCRYPT_DEBUG, 1, [Include scrypt debug support])
    fi

    PHP_ADD_INCLUDE(crypto)
    PHP_ADD_BUILD_DIR(crypto)

    AC_DEFINE(HAVE_SCRYPT, 1, [Whether you have scrypt])
    PHP_NEW_EXTENSION(scrypt, php_scrypt.c php_scrypt_utils.c crypto/sha256.c crypto/crypto_scrypt.c, $ext_shared)
fi