<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Application\CMSApplicationInterface;
use Joomla\CMS\Language\Text;
use Joomla\CMS\Log\Log;
use Joomla\CMS\Router\Route;
use Joomla\Registry\Registry;

/**
 * What the client is told: the page which refuses a blocked client, and the
 * messages about the attempts left. A failed login is answered at once: a
 * response held back on purpose would hold a PHP worker for as long, which
 * an attacker with many addresses could use to run the server out of them
 * (see the README, "Rate limiting").
 */
class Responder
{
	private CMSApplicationInterface $app;
	private Registry $params;
	private LoggerHelper $logger;

	public function __construct(CMSApplicationInterface $app, Registry $params, LoggerHelper $logger)
	{
		$this->app = $app;
		$this->params = $params;
		$this->logger = $logger;
	}

	private function isApi(): bool
	{
		return $this->app->isClient('api');
	}

	/**
	 * Whether the client of a failed login is told how many attempts it has
	 * left, or advised to reset the password: only on a page (an API client
	 * gets no messages shown), and if the settings ask for either.
	 */
	public function showsRemainingAttempts(): bool
	{
		$passwordReminder = Settings::int($this->params, 'notifyUsePasswordReminder');
		return !$this->isApi() &&
			(Settings::bool($this->params, 'notifyRemainingAttempts') ||
				$passwordReminder == -1 || $passwordReminder > 0);
	}

	/**
	 * Shows the client of a failed login the messages about the $attemptsLeft
	 * attempts it has before it is blocked, see showsRemainingAttempts().
	 * $recommendsPasswordReset: whether the recommendation of the password
	 * reset (if the settings ask for it) goes with it; not after a wrong
	 * second factor.
	 */
	public function showRemainingAttempts($attemptsLeft, bool $recommendsPasswordReset = true)
	{
		if ($attemptsLeft < 0)
		{
			$this->logger->log('Remaining attempts below zero ('.$attemptsLeft.'), that should not happen. ', Log::ERROR);
			return;
		}
		$passwordReminder = Settings::int($this->params, 'notifyUsePasswordReminder');
		if (Settings::bool($this->params, 'notifyRemainingAttempts') && $attemptsLeft > 0)
		{
			$this->app->enqueueMessage(Text::sprintf('PLG_SYSTEM_BFSTOP_X_ATTEMPTS_LEFT', $attemptsLeft), 'warning');
		}
		if ($recommendsPasswordReset && ($passwordReminder == -1 || $attemptsLeft <= $passwordReminder))
		{
			$this->app->enqueueMessage(Text::sprintf('PLG_SYSTEM_BFSTOP_PASSWORD_RESET_RECOMMENDED',
				Route::_('index.php?option=com_users&view=reset')), 'warning');
		}
	}

	/**
	 * Answers the request of the blocked client $ipaddress with the block
	 * page (or the API's error), and ends the request.
	 */
	public function refuseBlocked($ipaddress)
	{
		$status = self::blockedResponseCode(Settings::bool($this->params, 'useHttpError'));
		if ($status !== null)
		{
			http_response_code($status);
		}
		foreach (self::blockedResponseHeaders() as $header)
		{
			header($header);
		}
		$message = Settings::string($this->params, 'blockedMessage') ?: Text::_('PLG_SYSTEM_BFSTOP_BLOCKED_IP_MESSAGE');
		if (Settings::bool($this->params, 'blockedMsgShowIP'))
		{
			$message .= ' '.Text::sprintf('PLG_SYSTEM_BFSTOP_BLOCKED_CLIENT_IP', $ipaddress);
		}
		$this->send($message, $status);
	}

	/**
	 * Answers a login attempt whose address could not be checked against the
	 * block list: 503 (it is not refused for good), with Retry-After; and
	 * ends the request.
	 */
	public function refuseUnchecked()
	{
		http_response_code(503);
		header('Retry-After: 60');
		foreach (self::blockedResponseHeaders() as $header)
		{
			header($header);
		}
		$this->send(Text::_('PLG_SYSTEM_BFSTOP_LOGIN_UNAVAILABLE'), 503);
	}

	private function send($message, $status)
	{
		if ($this->isApi())
		{
			header('Content-Type: application/vnd.api+json; charset=utf-8');
			$message = self::blockedApiResponse($message, $status);
		}
		echo $message;
		$this->app->close();
	}

	/**
	 * The status code of the page shown to a blocked client, or null for none
	 * (which makes it 200). Set with http_response_code(), not as a raw
	 * "HTTP/1.x 403 ..." header: that would hard-code the protocol version,
	 * which is the web server's business (HTTP/2 doesn't even have a status line).
	 */
	public static function blockedResponseCode($useHttpError)
	{
		return $useHttpError ? 403 : null;
	}

	/**
	 * The headers of the page shown to a blocked client.
	 *
	 * It must never be cached: a cache (browser, proxy, CDN) which kept it
	 * would show it to other visitors of the same URL. It is no page of the
	 * site either: not for search engines (it is what a crawler gets for
	 * every address of the site while its own is blocked), and with its type
	 * and character set named - the server's defaults are not necessarily
	 * those of the message - and not to be guessed by the browser. Nor may
	 * another site show it in a frame (it is echoed without the template, so
	 * the headers the site's template or Joomla's HTTP headers plugin would
	 * send are missing): frame-ancestors for current browsers, X-Frame-Options
	 * for older ones.
	 */
	public static function blockedResponseHeaders()
	{
		return array(
			'Cache-Control: no-store, no-cache, must-revalidate, private',
			'Pragma: no-cache',
			'Content-Type: text/html; charset=utf-8',
			'X-Content-Type-Options: nosniff',
			"Content-Security-Policy: frame-ancestors 'none'",
			'X-Frame-Options: DENY',
			'X-Robots-Tag: noindex, nofollow',
		);
	}

	/**
	 * The body of the answer to a blocked API request: an error in the form
	 * the API answers others with (JSON:API, see Joomla's JsonapiRenderer).
	 */
	public static function blockedApiResponse($message, $status)
	{
		$error = array('title' => trim(html_entity_decode(strip_tags((string) $message), ENT_QUOTES | ENT_HTML5, 'UTF-8')));
		if ($status !== null)
		{
			$error['code'] = $status;
		}
		return json_encode(array('errors' => array($error)), JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
	}
}
