/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: 8b564912a6ddca2a4134bbff80f81e82ba20805e */

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_scrypt, 0, 6, MAY_BE_STRING|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, salt, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, N, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, r, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, p, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, key_length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO_WITH_DEFAULT_VALUE(0, raw_output, _IS_BOOL, 0, "false")
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_WITH_RETURN_TYPE_MASK_EX(arginfo_scrypt_pickparams, 0, 3, MAY_BE_ARRAY|MAY_BE_FALSE)
	ZEND_ARG_TYPE_INFO(0, max_memory, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, memory_fraction, IS_DOUBLE, 0)
	ZEND_ARG_TYPE_INFO(0, max_time, IS_DOUBLE, 0)
ZEND_END_ARG_INFO()


ZEND_FUNCTION(scrypt);
ZEND_FUNCTION(scrypt_pickparams);


static const zend_function_entry ext_functions[] = {
	ZEND_FE(scrypt, arginfo_scrypt)
	ZEND_FE(scrypt_pickparams, arginfo_scrypt_pickparams)
	ZEND_FE_END
};

static void register_php_scrypt_symbols(int module_number)
{

#if (PHP_VERSION_ID >= 80200)
	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "scrypt", sizeof("scrypt") - 1), 0, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);

	zend_add_parameter_attribute(zend_hash_str_find_ptr(CG(function_table), "scrypt", sizeof("scrypt") - 1), 1, ZSTR_KNOWN(ZEND_STR_SENSITIVEPARAMETER), 0);
#endif
}
