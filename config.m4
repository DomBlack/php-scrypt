PHP_ARG_ENABLE(scrypt, whether to enable scrypt support,
[ --enable-scrypt  Enable scrypt support])

if test $PHP_SCRYPT != "no"; then
    PHP_ADD_INCLUDE(crypto)
    PHP_ADD_BUILD_DIR(crypto)

    PHP_SUBST(SCRYPT_SHARED_LIBADD)
    PHP_CHECK_LIBRARY(rt, clock_gettime, [PHP_ADD_LIBRARY(rt,, SCRYPT_SHARED_LIBADD)])

    AH_TEMPLATE(HAVE_SYSCTL_HW_USERMEM, [Define if the hw.usermem property exists in sysctl.])
    if sysctl hw.usermem >/dev/null 2>/dev/null; then
        AC_DEFINE(HAVE_SYSCTL_HW_USERMEM, 1)
    fi

    AH_TEMPLATE(HAVE_CLOCK_GETTIME, [See if we have the clock_gettime function.])
    AH_TEMPLATE(HAVE_STRUCT_SYSINFO, [Define if the sysinfo struct exists.])
    AH_TEMPLATE(HAVE_STRUCT_SYSINFO_TOTALRAM, [Define if the sysinfo struct has a member for the total amount of RAM.])
	
    AC_SEARCH_LIBS([clock_gettime], [rt], [AC_DEFINE(HAVE_CLOCK_GETTIME, 1)])
    AC_CHECK_MEMBER([struct sysinfo.uptime], [AC_DEFINE(HAVE_STRUCT_SYSINFO)])
    AC_CHECK_MEMBER([struct sysinfo.totalram], [AC_DEFINE(HAVE_STRUCT_SYSINFO_TOTALRAM)])

    version=nosse
    if test "$(uname)" == 'Darwin'; then
        sysctl -a | grep -iq "^machdep.cpu.features.\+sse2"
    else
        grep -iq "^flags.\+sse2" /proc/cpuinfo
    fi
    if test $? == 0; then
        version=sse
        CFLAGS="$CFLAGS -msse -msse2"
    fi
    AC_DEFINE(HAVE_SCRYPT, 1, [Whether you have scrypt])
    PHP_NEW_EXTENSION(scrypt, php_scrypt.c php_scrypt_utils.c crypto/sha256.c crypto/crypto_scrypt-$version.c crypto/params.c, $ext_shared)

    ifdef([PHP_ADD_EXTENSION_DEP],
    [
        PHP_ADD_EXTENSION_DEP(scrypt, hash)
    ])
fi
