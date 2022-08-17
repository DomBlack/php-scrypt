/* This is a generated file, edit the .stub.php file instead.
 * Stub hash: ea5f25cdf40271f96836b23cdda89954e4c2a479 */

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
