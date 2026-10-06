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
// the database as it does in a real request (and may delay or block).
// Used by FailedLoginTest; needs the same environment as the tests.

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Event\Event;

require dirname(__DIR__, 2).'/bootstrap.php';

$_SERVER['REMOTE_ADDR'] = $argv[1];
$_SERVER['HTTP_USER_AGENT'] = 'Mozilla/5.0';
$app = Factory::getApplication();
PluginHelper::importPlugin('system', 'bfstop', true, $app->getDispatcher());
$app->getDispatcher()->dispatch('onUserLoginFailure',
	new Event('onUserLoginFailure', array(array('username' => $argv[2], 'status' => 4), array())));
echo "DONE\n";
