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
// "option=com_users&task=user.login").
// Used by PluginEventsTest; needs the same environment as the tests.

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Event\Event;

require dirname(__DIR__, 2).'/bootstrap.php';

$_SERVER['REMOTE_ADDR'] = $argv[1];
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
if (!in_array('--no-route', $argv, true))
{
	$app->getDispatcher()->dispatch('onAfterRoute', new Event('onAfterRoute', array()));
}
echo "NOT BLOCKED\n";
