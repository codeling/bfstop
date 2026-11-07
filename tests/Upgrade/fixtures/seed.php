<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Gives a site with the previous release installed (tests/ci/upgrade-test.sh)
// what a site that ran it for a while has, in the form that version kept it:
// settings saved in the Plugin Manager (with the switches 2.0 replaced by
// "blockMode"), and block list, allow list and failed logins as it wrote
// them - addresses not in the canonical form 2.0 looks them up in, user
// names differing in case only. UpgradeTest checks what the update made of it.

use Joomla\CMS\Factory;
use Joomla\Database\DatabaseInterface;

require dirname(__DIR__, 2).'/bootstrap.php';

$db = Factory::getContainer()->get(DatabaseInterface::class);
$now = date('Y-m-d H:i:s');

$params = array(
	'blockEnabled' => '1',
	'useHtaccess' => '0',
	'blockNumber' => '15',
	'delayDuration' => '90',
	'deleteOld' => '0',
	'logLevel' => '8',
	// backend only: 2.0.0 adds the Web Services API to it
	'enabledForOrigin' => '2',
);
$db->setQuery('UPDATE #__extensions SET enabled=1, params='.$db->quote(json_encode($params)).
	" WHERE type='plugin' AND folder='system' AND element='bfstop'");
$db->execute();

foreach (array('2001:DB8::5', '203.0.113.7/24', '198.51.100.9') as $address)
{
	$row = (object) array('ipaddress' => $address, 'crdate' => $now, 'duration' => 0);
	$db->insertObject('#__bfstop_bannedip', $row);
}
$row = (object) array('ipaddress' => 'ABCD::1', 'notes' => 'office');
$db->insertObject('#__bfstop_allowlist', $row);
foreach (array('admin', 'admin', 'Bob', 'bob', 'jürgen') as $username)
{
	$row = (object) array('username' => $username, 'ipaddress' => '192.0.2.1',
		'logtime' => $now, 'origin' => 0, 'handled' => 0);
	$db->insertObject('#__bfstop_failedlogin', $row);
}
echo "Seeded the site with settings and data of the previous release\n";
