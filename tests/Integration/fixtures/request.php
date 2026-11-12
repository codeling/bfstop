<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Simulates the start of a site request from the IP address given as first
// argument, as far as the plugin is concerned: prints the plugin's block
// message if it rejects the request, "NOT BLOCKED" otherwise. An optional
// second argument gives the request parameters as a query string (e.g.
// "option=com_users&task=user.login"). With --admin it is a request to the
// backend, by a guest, or with --admin=<username> by that user; with --api
// one to the Web Services API. --server=NAME=VALUE sets $_SERVER[NAME] (e.g.
// a header). --then=failure:USERNAME or --then=login:USERNAME lets the login
// of that user fail or succeed afterwards, and prints before and after it
// whether the request holds the lock for the logins of its address ("LOGIN
// TURN HELD" or "FREE", see Bfstop::awaitLoginTurn()).
// Used by PluginEventsTest; needs the same environment as the tests.

use Codeling\Plugin\System\Bfstop\Extension\Bfstop;
use Codeling\Plugin\System\Bfstop\Helper\IpHelper;
use Codeling\Plugin\System\Bfstop\Helper\LockHelper;
use Joomla\CMS\Application\AdministratorApplication;
use Joomla\CMS\Application\ApiApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\CMS\User\UserFactoryInterface;
use Joomla\Event\Event;

require dirname(__DIR__, 2).'/bootstrap.php';

$_SERVER['REMOTE_ADDR'] = $argv[1];
$isApi = in_array('--api', $argv, true);
if ($isApi)
{
	Factory::$application = Factory::getContainer()->get(ApiApplication::class);
	Factory::$application->createExtensionNamespaceMap();
	Factory::$application->loadLanguage();
}
foreach (array_slice($argv, 3) as $option)
{
	if (strncmp($option, '--server=', 9) === 0)
	{
		list($name, $value) = explode('=', substr($option, 9), 2);
		$_SERVER[$name] = $value;
	}
	if (strncmp($option, '--admin', 7) !== 0)
	{
		continue;
	}
	$container = Factory::getContainer();
	$container->alias('session.web.administrator', 'session.cli');
	$admin = $container->get(AdministratorApplication::class);
	Factory::$application = $admin;
	$admin->createExtensionNamespaceMap();
	$admin->loadLanguage();
	$username = (string) substr($option, 8);
	$admin->loadIdentity($username === '' ? null
		: $container->get(UserFactoryInterface::class)->loadUserByUsername($username));
}
$app = Factory::getApplication();
parse_str($argv[2] ?? '', $params);
foreach ($params as $name => $value)
{
	$app->input->set($name, $value);
}
// the plugin ends a blocked request with exit(), so report the response
// status it set when the script ends
register_shutdown_function(function ()
{
	echo "\nSTATUS: ".http_response_code()."\n";
});
PluginHelper::importPlugin('system', 'bfstop', true, $app->getDispatcher());
$app->getDispatcher()->dispatch('onAfterInitialise', new Event('onAfterInitialise', array()));
// blocking is enforced after routing (SEF URLs only yield option/view then)
// (the API has an event of its own for that)
if (!in_array('--no-route', $argv, true))
{
	$event = $isApi ? 'onAfterApiRoute' : 'onAfterRoute';
	$app->getDispatcher()->dispatch($event, new Event($event, array()));
}
echo "NOT BLOCKED\n";
foreach (array_slice($argv, 3) as $option)
{
	if (strncmp($option, '--then=', 7) !== 0)
	{
		continue;
	}
	// the lock is the request's if nobody else can take it (a second handle
	// of this process is somebody else to flock())
	$loginTurn = function () use ($argv)
	{
		$handle = LockHelper::acquire(Bfstop::loginTurnFile(
			IpHelper::trackedAddress($argv[1], Bfstop::DefaultSettings['ipv6PrefixLength'])), 0);
		LockHelper::release($handle);
		return 'LOGIN TURN '.($handle === null ? 'HELD' : 'FREE')."\n";
	};
	echo $loginTurn();
	list($outcome, $username) = explode(':', substr($option, 7), 2);
	$name = $outcome === 'login' ? 'onUserLogin' : 'onUserLoginFailure';
	$app->getDispatcher()->dispatch($name, new Event($name,
		array(array('username' => $username, 'status' => $outcome === 'login' ? 1 : 4), array())));
	echo $loginTurn();
}
