/*-
 * Copyright 2012 Dominic Black
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#ifdef PHP_WIN32
#include "zend_config.w32.h"
#endif
#include "ext/standard/info.h"
#include "ext/hash/php_hash.h"
#include "php_scrypt_utils.h"
#include "php_scrypt.h"
#include "crypto/crypto_scrypt.h"
#include "crypto/params.h"
#include "zend_exceptions.h"

static zend_class_entry *spl_ce_BadFunctionCallException;

static zend_function_entry scrypt_functions[] = {
    PHP_FE(scrypt, NULL)
    PHP_FE(scrypt_pickparams, NULL)
    {NULL, NULL, NULL}
};

zend_module_entry scrypt_module_entry = {
#if ZEND_MODULE_API_NO >= 20010901
    STANDARD_MODULE_HEADER,
#endif
    PHP_SCRYPT_EXTNAME,
    scrypt_functions,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
#if ZEND_MODULE_API_NO >= 20010901
    PHP_SCRYPT_VERSION,
#endif
    STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_SCRYPT
ZEND_GET_MODULE(scrypt)
#endif

/*
 * The scrypt wrapper for PHP
 *
 * This takes a call such as:
 *   scrypt($password, $salt, $N, $r, $p)
 *
 * Where;
 *     string $password  The user's password
 *     string $salt      The user's salt
 *     long   $N         The CPU difficultly (must be a power of 2, greater than 1)
 *     int    $r         The memory difficulty
 *     int    $p         The parallel difficulty
 *     int    $keyLength The length of hash
 *
 * The parameters $r, $p must satisfy; $r * $p < 2^30
 * The parameter $keyLength must satisfy; $keyLength <= (2^32 - 1) * 32.
 * The parameter $N must be a power of 2 greater than 1.
 *
 * This function will return a hex encoded version of the binary hash.
 */
PHP_FUNCTION(scrypt)
{
    //Variables for PHP's parameters
    char *password;
    int password_len;

    char *salt;
    int salt_len;

    long phpN; //16384
    long phpR; //8
    long phpP; //1
    long keyLength; //32

    zend_bool raw_output;

    //Casted variables for scrypt
    uint64_t cryptN;
    uint32_t cryptR;
    uint32_t cryptP;


    //Output variables
    unsigned char *hex;
    unsigned char *buf;

    int result;

    //Get the parameters for this call
    phpN = -1;
    phpR = -1;
    phpP = -1;
    keyLength = 64;
    raw_output = 0;
    if (zend_parse_parameters(
            ZEND_NUM_ARGS() TSRMLS_CC, "ssllll|b",
            &password, &password_len, &salt, &salt_len,
            &phpN, &phpR, &phpP, &keyLength, &raw_output
        ) == FAILURE)
    {
        return;
    }

    //Clamp & cast them
    cryptN = clampAndCast64("N", phpN);
    cryptR = clampAndCast64("r", phpR);
    cryptP = clampAndCast64("p", phpP);

    if (keyLength < 16) {
        keyLength = -1;
        php_error(1, "Key length is too low, must be greater or equal to 16");
    } else if (keyLength > 137438953440) { //(2^32 - 1) * 32
        keyLength = -1;
        php_error(1, "Key length is too high, must be no more than 137438953440");
    }

    //Return out if we've encountered a error with the input parameters
    if (cryptN < 0 || cryptR < 0 || cryptP < 0 || keyLength < 0) {
        RETURN_BOOL(0);
    }

    //Allocate the memory for the output of the key
    buf = (unsigned char*)emalloc(keyLength + 1);

    //Call the scrypt function
    result = crypto_scrypt(
        password, password_len, salt, salt_len, //Input
        cryptN, cryptR, cryptP, //Settings
        buf, keyLength //Output
    );

    //Check the crypto returned the hash we wanted.
    if (result != 0) {
        efree(buf);
        RETURN_BOOL(0);
    }

    if(!raw_output) {
        //Encode the output in hex
        hex = (unsigned char*) emalloc(keyLength * 2 + 1);
        php_hash_bin2hex(hex, buf, keyLength);
        efree(buf);
        RETURN_STRINGL(hex, keyLength * 2, 0);
    } else {
        RETURN_STRINGL(buf, keyLength, 0);
    }
}

/*
 * Automatically pick parameters for scrypt
 *
 * This takes a call such as:
 *   scrypt_pickparams($maxmem, $memfrac, $maxtime)
 *
 * Where;
 *     long   $maxmem  Maximum amount of memory to use
 *     double $memfrac Maximum fraction of available memory to use
 *     double $maxtime Maximum CPU time to use
 *
 * This function will return an array with the N, r, and p
 * parameters for use in the scrypt() function.
 */
PHP_FUNCTION(scrypt_pickparams)
{
#ifdef PHP_WIN32
    zend_throw_error_exception(
        spl_ce_BadFunctionCallException,
        "Function not implemented in Windows.",
        0 TSRMLS_CC
    );
#else
    long maxmem;
    double memfrac, maxtime;

    int cryptN;
    uint32_t cryptR;
    uint32_t cryptP;

    long phpN, phpP, phpR;

    int rc;

    //Get the parameters for this call
    if (zend_parse_parameters(
            ZEND_NUM_ARGS() TSRMLS_CC, "ldd",
            &maxmem, &memfrac, &maxtime
        ) == FAILURE)
    {
        return;
    }

    if(maxmem < 0 || memfrac < 0 || maxtime < 0) {
        RETURN_FALSE;
    }

    rc = pickparams((size_t) maxmem, memfrac, maxtime, &cryptN, &cryptR, &cryptP);

    if(rc != 0) {
        php_error(1, "Could not determine scrypt parameters.");
        RETURN_FALSE;
    }

    phpN = (long) cryptN;
    phpR = (long) cryptR;
    phpP = (long) cryptP;

    array_init(return_value);
    add_assoc_long(return_value, "n", phpN);
    add_assoc_long(return_value, "r", phpR);
    add_assoc_long(return_value, "p", phpP);
    return;
#endif
}
