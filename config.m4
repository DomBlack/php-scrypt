PHP_ARG_ENABLE(scrypt, whether to enable scrypt support,
[ --enable-scrypt  Enable scrypt support])

if test $PHP_SCRYPT != "no"; then
    PHP_ADD_INCLUDE(crypto)
    PHP_ADD_BUILD_DIR(crypto)

    version=nosse
    AC_CHECK_HEADER([emmintrin.h], [version=sse], [version=nosse])
    AC_DEFINE(HAVE_SCRYPT, 1, [Whether you have scrypt])
    PHP_NEW_EXTENSION(scrypt, php_scrypt.c php_scrypt_utils.c crypto/sha256.c crypto/crypto_scrypt-$version.c, $ext_shared)
fi
