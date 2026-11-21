<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Makes the probe directory given as first argument, with the token given as
// second, as the settings page's check of the .htaccess file does (see
// HtaccessHelper::writeProbe()). Needs only the library's own classes, not
// Joomla. Used by tests/ci/apache-htaccess.sh.

define('_JEXEC', 1);
spl_autoload_register(function ($class)
{
	$prefix = 'Codeling\\Library\\Bfstop\\';
	if (strncmp($class, $prefix, strlen($prefix)) === 0)
	{
		require dirname(__DIR__, 3).'/library/src/'.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
	}
});

exit(Codeling\Library\Bfstop\Helper\HtaccessHelper::writeProbe($argv[1], $argv[2]) ? 0 : 1);
