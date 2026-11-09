<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Simulates a failed login with the username given as second argument from
// the IP address given as first argument, as far as the plugin is concerned:
// dispatches onUserLoginFailure to the plugin, which reads its settings from
// the database as it does in a real request (and may delay or block). With
// --api it is a failed login to the Web Services API (whose response holds
// no username), --server=NAME=VALUE sets $_SERVER[NAME] (e.g. a header),
// --live-site=URL the site's $live_site.
// Used by FailedLoginTest; needs the same environment as the tests.

use Joomla\CMS\Application\ApiApplication;
use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Event\Event;

require dirname(__DIR__, 2).'/bootstrap.php';

$_SERVER['REMOTE_ADDR'] = $argv[1];
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
foreach (array_slice($argv, 3) as $option)
{
	if (strncmp($option, '--server=', 9) === 0)
	{
		list($name, $value) = explode('=', substr($option, 9), 2);
		$_SERVER[$name] = $value;
	}
}
if (in_array('--api', $argv, true))
{
	Factory::$application = Factory::getContainer()->get(ApiApplication::class);
	Factory::$application->createExtensionNamespaceMap();
	Factory::$application->loadLanguage();
}
$app = Factory::getApplication();
foreach (array_slice($argv, 3) as $option)
{
	if (strncmp($option, '--live-site=', 12) === 0)
	{
		$app->set('live_site', substr($option, 12));
	}
}
PluginHelper::importPlugin('system', 'bfstop', true, $app->getDispatcher());
$app->getDispatcher()->dispatch('onUserLoginFailure',
	new Event('onUserLoginFailure', array(array('username' => $argv[2], 'status' => 4), array())));
echo "DONE\n";
