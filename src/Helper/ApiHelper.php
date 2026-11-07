<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Helper;

defined('_JEXEC') or die;

/**
 * Requests to Joomla's Web Services API (api/index.php) carry their
 * credentials with every request: an API token (Joomla's "API
 * Authentication - Web Services Joomla Token" plugin, header
 * "Authorization: Bearer ..." or "X-Joomla-Token") or a username and
 * password (the "API Authentication - HTTP Basic" plugin). Joomla tries to
 * log in every request to an endpoint which isn't public, also one without
 * any credentials, and reports a failed login for it - with an empty
 * username either way, as the authentication plugins don't pass on what
 * they were given.
 */
class ApiHelper
{
	/**
	 * The username of the credentials an API request carries: the one of
	 * HTTP Basic authentication, '' for a token (it names its user by id
	 * only) - or null if the request carries no credentials at all, which
	 * makes its failed login no attempt to guess any.
	 *
	 * @param array       $server              $_SERVER of the request
	 * @param string|null $authorizationHeader the Authorization header, if
	 *                                         the web server didn't put it
	 *                                         into $server
	 */
	public static function credentialsUsername(array $server, ?string $authorizationHeader = null): ?string
	{
		$value = function ($name) use ($server)
		{
			return (isset($server[$name]) && is_string($server[$name])) ? $server[$name] : '';
		};
		if ($value('PHP_AUTH_USER') !== '' || $value('PHP_AUTH_PW') !== '')
		{
			return $value('PHP_AUTH_USER');
		}
		$authorization = trim($value('HTTP_AUTHORIZATION') !== '' ? $value('HTTP_AUTHORIZATION')
			: ($value('REDIRECT_HTTP_AUTHORIZATION') !== '' ? $value('REDIRECT_HTTP_AUTHORIZATION')
				: (string) $authorizationHeader));
		if (strncasecmp($authorization, 'Basic ', 6) === 0)
		{
			$decoded = base64_decode(trim(substr($authorization, 6)), true);
			return ($decoded === false) ? '' : explode(':', $decoded, 2)[0];
		}
		if ($authorization !== '' || trim($value('HTTP_X_JOOMLA_TOKEN')) !== '')
		{
			return '';
		}
		return null;
	}

	/**
	 * credentialsUsername() for the current request.
	 */
	public static function requestCredentialsUsername(): ?string
	{
		$authorizationHeader = null;
		// with mod_php, Apache doesn't always pass the header on in $_SERVER;
		// Joomla's token plugin looks for it the same way
		if (empty($_SERVER['HTTP_AUTHORIZATION']) && function_exists('apache_request_headers'))
		{
			$headers = apache_request_headers();
			if (is_array($headers))
			{
				$headers = array_change_key_case($headers, CASE_LOWER);
				$authorizationHeader = isset($headers['authorization']) ? (string) $headers['authorization'] : null;
			}
		}
		return self::credentialsUsername($_SERVER, $authorizationHeader);
	}
}
