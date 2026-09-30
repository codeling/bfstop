<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Simulates the start of a site request from the IP address given as first
// argument, as far as the plugin is concerned: prints the plugin's block
// message if it rejects the request, "NOT BLOCKED" otherwise.
// Used by PluginEventsTest; needs the same environment as the tests.

use Joomla\CMS\Factory;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Event\Event;

require dirname(__DIR__, 2).'/bootstrap.php';

$_SERVER['REMOTE_ADDR'] = $argv[1];
$app = Factory::getApplication();
PluginHelper::importPlugin('system', 'bfstop', true, $app->getDispatcher());
$app->getDispatcher()->dispatch('onAfterInitialise', new Event('onAfterInitialise', array()));
echo "NOT BLOCKED\n";
