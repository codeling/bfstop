<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Service;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\ApiHelper;
use Joomla\CMS\Application\CMSApplicationInterface;

/**
 * What a request does, as far as blocking is concerned: whether it submits a
 * login, is the unblock page, or the password recovery - the requests a
 * blocked client may or may not make.
 *
 * Joomla doesn't say what it will run for a request until it runs it, so
 * this works it out the way Joomla's code does: the component as
 * AdministratorApplication::findOption() picks it, the controller and method
 * as ComponentDispatcher::dispatch() and BaseController::execute() take them
 * from "task" and "controller". Those are Joomla's internals, not an API: if
 * Joomla handles a request differently from what this expects, a request it
 * doesn't recognise gets past the block. RequestClassifierTest therefore
 * compares the answers with what the Joomla version under test does, on
 * every version of the CI matrix (see tests/README.md).
 */
class RequestClassifier
{
	// the components the backend runs for a guest (or a user who may not log in
	// there) as requested; every other request goes to com_login, see
	// AdministratorApplication::$allowedUnprivilegedOptions
	public const UnprivilegedBackendOptions = array('com_login', 'com_ajax');

	// the tasks of com_users (controller.method) with which a user who forgot
	// their password or username gets a new one: the forms of the reset and
	// remind views post to them (index.php?task=reset.request, ...)
	public const PasswordRecoveryTasks = array(
		'reset.request',
		'reset.confirm',
		'reset.complete',
		'remind.remind',
		'user.remind',
	);

	private CMSApplicationInterface $app;

	public function __construct(CMSApplicationInterface $app)
	{
		$this->app = $app;
	}

	public function isApi(): bool
	{
		return $this->app->isClient('api');
	}

	/**
	 * A request parameter as a string: "option[]=x" and the like give arrays,
	 * which strcmp() and friends don't take (a TypeError on PHP 8, i.e. an
	 * error page instead of the intended answer). Such a value is returned as
	 * a NUL character: not empty - so it doesn't pass for "parameter not
	 * given" - and not equal to anything the parameter can legitimately be.
	 */
	public function requestString($name, $filter = 'cmd'): string
	{
		$value = $this->app->getInput()->get($name, '', $filter);
		return is_string($value) ? $value : "\0";
	}

	/**
	 * The controller and the method of it which Joomla's component dispatcher
	 * runs for this request, in lower case, as it determines them
	 * (ComponentDispatcher::dispatch(), BaseController::execute()): "task" is
	 * either "controller.method" - anything after a second dot is ignored - or
	 * just the method, with the controller from the "controller" parameter;
	 * the method's case doesn't matter. The method is '' if there is no task:
	 * the controller's default task runs then, which shows a view. Checks of
	 * the task have to go by this, not by the raw parameter, or
	 * "task=user.LOGIN" or "task=user.login.x" would not be recognised as the
	 * login they are.
	 *
	 * @return string[] array(controller, method)
	 */
	public function requestedTask(): array
	{
		$task = strtolower($this->requestString('task'));
		if (strpos($task, '.') !== false)
		{
			$parts = explode('.', $task);
			return array($parts[0], $parts[1]);
		}
		$controller = strtolower($this->requestString('controller'));
		return array($controller === '' ? 'display' : $controller, $task);
	}

	/**
	 * The component Joomla runs for this request, in lower case. Usually the
	 * "option" parameter, but not in the backend: there,
	 * AdministratorApplication::findOption() - called when the request is
	 * dispatched, after onAfterRoute - runs com_login for a guest, whatever
	 * else the request names, and com_cpanel if it names nothing. Checks of
	 * the component have to go by that, or a login posted to the backend
	 * with "option" left out (or set to any other component) would not be
	 * recognised as the login it is.
	 */
	public function requestedOption(): string
	{
		$option = strtolower($this->requestString('option'));
		if (!$this->app->isClient('administrator'))
		{
			return $option;
		}
		$user = $this->app->getIdentity();
		if (($user === null || $user->guest || !$user->authorise('core.login.admin')) &&
			!in_array($option, self::UnprivilegedBackendOptions, true))
		{
			return 'com_login';
		}
		return $option === '' ? 'com_cpanel' : $option;
	}

	/**
	 * Whether this is the request of com_bfstop's unblock page - a page of the
	 * site, which shows the view and runs no task - with the token it names
	 * (whether that is valid, the caller finds out). The check has to stay
	 * this narrow: that request is the one that consumes the token, which
	 * lets a blocked client through. Letting any request with
	 * view=tokenunblock through would turn a single valid token - which the
	 * owner of any account can get emailed by getting themselves blocked -
	 * into a reusable key around the block for logins (e.g.
	 * option=com_users&task=user.login&view=tokenunblock&token=...).
	 *
	 * @return string|null the token, null if it is no request of the unblock page
	 */
	public function unblockPageToken(): ?string
	{
		// in the backend, the request of a guest would go to com_login (see
		// requestedOption())
		if (!$this->app->isClient('site') ||
			$this->requestString('option') !== 'com_bfstop' ||
			$this->requestString('view') !== 'tokenunblock' ||
			$this->requestString('task') !== '')
		{
			return null;
		}
		return $this->requestString('token', 'string');
	}

	/**
	 * Password reset / username reminder must stay reachable even for a
	 * blocked IP - otherwise a legitimate user who got blocked (and is told
	 * by this very plugin to use password reset, see
	 * Responder::showRemainingAttempts()) would have no way to actually act
	 * on that advice, turning the block itself into a denial-of-service
	 * against them (see OWASP Authentication Cheat Sheet guidance on
	 * lockouts).
	 *
	 * That is: showing the reset and remind views, and submitting their
	 * forms - nothing else. In particular not any task with view=reset: the
	 * task is what Joomla runs, the view is ignored then, so that would let a
	 * blocked IP log in (option=com_users&view=reset&task=user.login). The
	 * site has these pages, the backend and the API don't.
	 *
	 * @return string|null what of the password recovery the request is ("view
	 *                     reset", "task reset.request", ...), null if it is none
	 */
	public function passwordRecovery(): ?string
	{
		if (!$this->app->isClient('site') || $this->requestedOption() !== 'com_users')
		{
			return null;
		}
		list($controller, $method) = $this->requestedTask();
		if ($method === '' || ($controller === 'display' && $method === 'display'))
		{
			$view = strtolower($this->requestString('view'));
			return ($view === 'reset' || $view === 'remind') ? 'view '.$view : null;
		}
		return in_array($controller.'.'.$method, self::PasswordRecoveryTasks, true)
			? 'task '.$controller.'.'.$method
			: null;
	}

	/**
	 * Detects a request that actually submits login credentials, for
	 * "Login Only" block mode (issue #187): on the frontend, credentials
	 * are submitted to com_users (task=user.login), the backend login form
	 * posts to com_login (task=login) - merely viewing the login form (no
	 * task, or a display task) doesn't match, so it stays reachable.
	 *
	 * The task is compared as Joomla's dispatcher runs it (see
	 * requestedTask()): the login method of whatever controller, in any case
	 * - "task=user.LOGIN", "task=user.login.x" and
	 * "controller=user&task=login" are all logins. Matching more than
	 * Joomla would run only blocks a request which wouldn't do anything.
	 * The same goes for the component (see requestedOption()): a backend
	 * login without "option=com_login" is a login all the same.
	 */
	public function isLoginAttempt(): bool
	{
		if ($this->isApi())
		{
			// an API request carries its credentials with it, each one with
			// them is a login (see ApiHelper)
			return ApiHelper::requestCredentialsUsername() !== null;
		}
		$option = $this->requestedOption();
		list(, $method) = $this->requestedTask();
		return ($option === 'com_users' || $option === 'com_login') && $method === 'login';
	}

	/**
	 * Whether the request submits a username and a password - what can be
	 * guessed: a login as isLoginAttempt() recognises it, but of the API
	 * requests only those with HTTP Basic credentials, not those with a token
	 * (a long random value, and what nearly every API request carries).
	 */
	public function isPasswordLogin(): bool
	{
		return $this->isApi()
			? ApiHelper::requestCredentialsArePassword()
			: $this->isLoginAttempt();
	}
}
