<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Integration;

/**
 * The link to the unblock page goes to the site, whichever application the
 * failed logins that got the address blocked went to. Joomla derives its
 * addresses (Uri::base(), Uri::root()) from the script name of the request
 * only outside the CLI - PHP's built-in web server counts as CLI too - so
 * this runs a script in each application's directory through php-cgi, as a
 * web server would.
 */
class UnblockLinkTest extends IntegrationTestCase
{
	private const Expected = 'http://www.example.org/index.php?option=com_bfstop&view=tokenunblock&token=T0KEN';

	private function linkBuiltIn($cgi, $directory)
	{
		$root = realpath(getenv('JOOMLA_ROOT'));
		$probe = $root.$directory.'/bfstop-unblock-link-test.php';
		$apps = array('' => 'SiteApplication', '/administrator' => 'AdministratorApplication', '/api' => 'ApiApplication');
		file_put_contents($probe, '<?php
define("_JEXEC", 1);
define("JPATH_BASE", __DIR__);
require JPATH_BASE."/includes/defines.php";
require JPATH_BASE."/includes/framework.php";
require '.var_export(dirname(__DIR__, 2).'/src/Extension/Bfstop.php', true).';
$c = \\Joomla\\CMS\\Factory::getContainer();
foreach (array("session.web.site", "session.web.administrator", \\Joomla\\Session\\SessionInterface::class) as $alias)
{
	$c->alias($alias, "session.cli");
}
\\Joomla\\CMS\\Factory::$application = $c->get(\\Joomla\\CMS\\Application\\'.$apps[$directory].'::class);
echo "\nLINK: ", \\Codeling\\Plugin\\System\\Bfstop\\Extension\\Bfstop::unblockLink("T0KEN"), "\n";
');
		try
		{
			$env = array('REDIRECT_STATUS' => '1', 'GATEWAY_INTERFACE' => 'CGI/1.1', 'REQUEST_METHOD' => 'GET',
				'SCRIPT_FILENAME' => $probe, 'SCRIPT_NAME' => $directory.'/bfstop-unblock-link-test.php',
				'REQUEST_URI' => $directory.'/bfstop-unblock-link-test.php', 'HTTP_HOST' => 'www.example.org',
				'SERVER_NAME' => 'www.example.org', 'SERVER_PORT' => '80', 'REMOTE_ADDR' => '192.0.2.1');
			$process = proc_open(array($cgi, '-d', 'display_errors=1', $probe), array(1 => array('pipe', 'w'), 2 => array('pipe', 'w')), $pipes, null, $env);
			$output = stream_get_contents($pipes[1]).stream_get_contents($pipes[2]);
			proc_close($process);
			$this->assertSame(1, preg_match('/^LINK: (.*)$/m', $output, $m), $output);
			return trim($m[1]);
		}
		finally
		{
			@unlink($probe);
		}
	}

	public function testUnblockLinkGoesToTheSiteFromEveryApplication()
	{
		$cgi = trim((string) shell_exec('command -v php-cgi 2>/dev/null'));
		if ($cgi === '')
		{
			$this->markTestSkipped('php-cgi is not installed');
		}
		// a block caused by failed logins through the API mailed a link into
		// api/, where there is no unblock page
		foreach (array('' => 'site', '/administrator' => 'backend', '/api' => 'API') as $directory => $name)
		{
			$this->assertSame(self::Expected, $this->linkBuiltIn($cgi, $directory), $name);
		}
	}
}
