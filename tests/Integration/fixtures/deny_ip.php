<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Adds the IP address given as second argument to the .htaccess file in the
// directory given as first argument, like the plugin does when it blocks an
// address. Needs only the plugin's own classes, not Joomla.
// Used by HtaccessHelperTest.

define('_JEXEC', 1);
spl_autoload_register(function ($class)
{
	$prefix = 'Codeling\\Plugin\\System\\Bfstop\\';
	if (strncmp($class, $prefix, strlen($prefix)) === 0)
	{
		require dirname(__DIR__, 3).'/src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
	}
});

$result = (new Codeling\Plugin\System\Bfstop\Helper\HtaccessHelper($argv[1], null))->denyIP($argv[2]);
exit($result === false ? 1 : 0);
