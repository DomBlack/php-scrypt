<?php
/**
 * This file contains wrapper and helper classes for the scrypt extension.
 *
 * PHP version 5
 *
 * @category Security
 * @package  Scrypt
 * @author   Dominic Black <thephenix@gmail.com>
 * @license  http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link     http://github.com/DomBlack/php-scrypt
 */
namespace Security\Scrypt;

/**
 * This class abstracts away from scrypt module, allowing for easy use.
 *
 * Change the application pepper to something random for yourself.
 *
 * You can create a new hash for a password by calling Password::hash($password)
 *
 * You can check a password by calling Password::check($password, $hash)
 *
 * @category Security
 * @package  Scrypt
 * @author   Dominic Black <thephenix@gmail.com>
 * @license  http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link     http://github.com/DomBlack/php-scrypt
 */
class Scrypt
{
    /**
     * @var int The key length
     */
    private $_keyLength = 32;

    /**
     * @var An application pepper (set to null for none)
     */
    private $_pepper = 'qi$1IeXl?$Oa_ia7';

    /**
     * Constructor for an Scrypt password.
     */
    public function __construct()
    {
        // Does nothing
    }

    /**
     * Generates a random salt
     *
     * @param int $length The length of the salt
     *
     * @throws ParametersIncorrectException Length must not be zero.
     *
     * @return string The salt
     */
    public function generateSalt($length = 8)
    {
        if ($length === 0) {
            throw new ParametersIncorrectException("Length must not be zero.");
        }

        $salt = '';
        $possibleChars = '0123456789abcdefghijklmnopqrstuvwxyz';
        $noOfChars = strlen($possibleChars) - 1;

        for ($i = 0; $i < $length; $i++) {
            $salt .= $possibleChars[mt_rand(0, $noOfChars)];
        }

        return $salt;
    }

    /**
     * Create a password hash
     *
     * @param string $password The clear text password
     * @param string $salt     The salt to use, or null to generate a random one
     * @param int    $N        The CPU difficulty
     *                         (must be even and a power of 2 and greater than 1)
     * @param int    $r        The memory difficulty ( > 0 )
     * @param int    $p        The parallel difficulty ( > 0 )
     *
     * @throws ParametersIncorrectException Password length must not be zero.
     * @throws ParametersIncorrectException Salt length must not be zero.
     * @throws ParametersIncorrectException CPU difficulty must be a power of two.
     * @throws ParametersIncorrectException Memory difficulty must be
     *                                      greater than one.
     * @throws ParametersIncorrectException Parallel difficulty must be
     *                                      greater than one.
     *
     * @return string The hashed password
     */
    public function hash(
        $password, $salt = false, $N = 16384, $r = 8, $p = 1
    ) {
        // Check password length is long enough.
        if (strlen($password) === 0) {
            throw new ParametersIncorrectException(
                "Password length must not be zero."
            );
        }

        if ($salt === false) {
            $salt = $this->generateSalt();
        } else {
            if (strlen($salt) === 0) {
                throw new ParametersIncorrectException(
                    "Salt length must not be zero."
                );
            }
            //Remove dollar signs from the salt, as we use that as a separator.
            $salt = str_replace('$', '', $salt);
        }

        // Check that the CPU difficulty is a power of 2 and greater than 1.
        // This will also check that $N is even.
        if ((($N & ($N - 1)) != 0) || $N <= 1) {
            throw new ParametersIncorrectException(
                "CPU difficulty must be a power of two."
            );
        }

        // Check that the memory difficulty is greater than 1.
        if ($r <= 1) {
            throw new ParametersIncorrectException(
                "Memory difficulty must be greater than one."
            );
        }

        if ($p <= 1) {
            throw new ParametersIncorrectException(
                "Parallel difficulty must be greater than one."
            );
        }

        $hash = scrypt(
            $password, $this->_pepper.$salt, $N, $r, $p, $this->_keyLength
        );

        return $N.'$'.$r.'$'.$p.'$'.$salt.'$'.$hash;
    }

    /**
     * Check a clear text password against a hash
     *
     * @param string $password The clear text password
     * @param string $hash     The hashed password
     *
     * @throws ParametersIncorrectException Hash length must be greater than zero.
     * @throws ParametersIncorrectException CPU difficulty must be a power of two.
     * @throws ParametersIncorrectException Memory difficulty must be
     *                                      greater than one.
     * @throws ParametersIncorrectException Parallel difficulty must be
     *                                      greater than one.
     *
     * @return boolean If the clear text matches
     */
    public function check($password, $hash)
    {
        if (strlen($hash) == 0) {
            throw new ParametersIncorrectException(
                "Hash length must be greater than zero."
            );
        }

        $parts = explode("$", $hash);
        if (count($parts) !== 5) {
            throw new ParametersIncorrectException(
                "Hash didn't have required number of parts."
            );
        }

        list($N, $r, $p, $salt, $hash) = explode('$', $hash);

        // Check that the CPU difficulty is a power of 2 and greater than 1.
        // This will also check that $N is even.
        if ((($N & ($N - 1)) != 0) || $N <= 1) {
            throw new ParametersIncorrectException(
                "CPU difficulty must be a power of two."
            );
        }

        // Check that the memory difficulty is greater than 1.
        if ($r <= 1) {
            throw new ParametersIncorrectException(
                "Memory difficulty must be greater than one."
            );
        }

        if ($p <= 1) {
            throw new ParametersIncorrectException(
                "Parallel difficulty must be greater than one."
            );
        }

        $calculated = scrypt(
            $password, $this->_pepper.$salt,
            $N, $r, $p,
            $this->_keyLength
        );

        return ($calculated == $hash);
    }
}

/**
 * Exception class for when the parameters being passed into scrypt aren't of
 * the correct form.
 *
 * @category   Security
 * @package    Scrypt
 * @author     Dominic Orme <dominic.orme@sensatus.com>
 * @license    http://www.opensource.org/licenses/BSD-2-Clause BSD 2-Clause License
 * @link       http://github.com/DomBlack/php-scrypt
 */
class ParametersIncorrectException extends \Exception
{
}
?>