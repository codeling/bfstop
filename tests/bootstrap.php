<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
// Test bootstrap, see tests/README.md. Unit tests only need the plugin
// sources; the integration tests additionally need an installed Joomla site
// (environment variable JOOMLA_ROOT), which is booted here as a site
// application. The classes of the plugin (and of the component, if
// COM_BFSTOP_ROOT is set) are always loaded from the source checkouts, not
// from the copies installed into that Joomla site.

use Joomla\CMS\Application\SiteApplication;
use Joomla\CMS\Factory;

if (!defined('_JEXEC'))
{
	define('_JEXEC', 1);
}

$joomlaRoot = getenv('JOOMLA_ROOT');
if ($joomlaRoot)
{
	// resolved: Joomla refuses paths containing ".."
	define('JPATH_BASE', realpath($joomlaRoot));
	require JPATH_BASE.'/includes/defines.php';
	require JPATH_BASE.'/includes/framework.php';

	// the site application derives its URLs from the request
	$_SERVER['HTTP_HOST'] = 'localhost';
	$_SERVER['SCRIPT_NAME'] = $_SERVER['PHP_SELF'] = '/index.php';
	$_SERVER['REQUEST_URI'] = '/';
	$_SERVER['REMOTE_ADDR'] = '127.0.0.1';

	$container = Factory::getContainer();
	// no web session in CLI (headers can't be sent)
	foreach (array('session', 'session.web', 'session.web.site', 'JSession',
		\Joomla\CMS\Session\Session::class, \Joomla\Session\Session::class,
		\Joomla\Session\SessionInterface::class) as $alias)
	{
		$container->alias($alias, 'session.cli');
	}
	$app = $container->get(SiteApplication::class);
	Factory::$application = $app;
	$app->createExtensionNamespaceMap();
	// as in a real request, the language is loaded before any plugin (plugins
	// only load their own language strings if there already is one)
	$app->loadLanguage();
}

$sourceNamespaces = array(
	'Codeling\\Plugin\\System\\Bfstop\\' => dirname(__DIR__).'/src/',
);
$comRoot = getenv('COM_BFSTOP_ROOT');
if ($comRoot)
{
	$comRoot = realpath($comRoot);
	$sourceNamespaces['Codeling\\Component\\Bfstop\\Administrator\\'] = $comRoot.'/admin/src/';
	$sourceNamespaces['Codeling\\Component\\Bfstop\\Site\\'] = $comRoot.'/site/src/';
}
$sourceNamespaces['Codeling\\Bfstop\\Tests\\'] = __DIR__.'/';
spl_autoload_register(function ($class) use ($sourceNamespaces)
{
	foreach ($sourceNamespaces as $prefix => $dir)
	{
		if (strncmp($class, $prefix, strlen($prefix)) === 0)
		{
			$file = $dir.str_replace('\\', '/', substr($class, strlen($prefix))).'.php';
			if (is_file($file))
			{
				require $file;
				return;
			}
		}
	}
}, true, true);
