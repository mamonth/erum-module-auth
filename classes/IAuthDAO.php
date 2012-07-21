<?php
namespace Auth;

/**
 * Description of IAuthDAO
 *
 * @author Andrew Tereshko <andrew.tereshko@gmail.com>
 */
interface IAuthDAO
{
    public static function authRequest( $login, $password );
}
