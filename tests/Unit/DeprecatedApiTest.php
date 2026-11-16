<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use PHPUnit\Framework\TestCase;

/**
 * Joomla! 5.x and 6.x deprecate these (most are removed in 7.0), and the
 * replacements exist since Joomla! 5.4 - the minimum version of BFStop - or
 * earlier. Fails if one of the old forms comes back into the plugin, the
 * component or the package.
 */
class DeprecatedApiTest extends TestCase
{
	/** old form => what to use */
	private const Deprecated = array(
		'/Factory::getDbo\(/' => 'the DatabaseInterface of the container (or $this->getDatabase() in a model)',
		'/Factory::getConfig\(/' => 'Factory::getApplication()->get()',
		'/Factory::getSession\(/' => '$app->getSession()',
		'/Factory::getLanguage\(/' => '$app->getLanguage()',
		'/Factory::getDocument\(/' => '$app->getDocument() (in a view: $this->getDocument())',
		'/Factory::getMailer\(/' => 'MailerFactoryInterface from the container',
		'/Factory::getUser\(/' => '$app->getIdentity()',
		'/Factory::getCache\(/' => 'CacheControllerFactoryInterface from the container',
		'/Factory::getDate\(/' => 'new Joomla\CMS\Date\Date()',
		'/->getCfg\(/' => '->get()',
		'/->_db\b/' => '$this->getDatabase()',
		'/Table::getInstance\(/' => 'the MVC factory (createTable) or the table class itself',
		'/->addStyleSheet\(|->addScript\(|->addScriptDeclaration\(|->addStyleDeclaration\(/' => 'the WebAssetManager',
		'/\$this->get\(\'/' => '$this->getModel()->getXyz() in a view',
		'/(Factory::getApplication\(\)|\$app|\$application|\$this->getApplication\(\))->input\b/' => '->getInput()',
		'/->getArgument\(\s*\d/' => 'the typed event\'s getter (getAuthenticationResponse(), ...)',
		'/new\s+\w+\(\s*\$dispatcher\b/' => 'new Plugin($config); Joomla sets the dispatcher',
		'/_f2\.png/' => 'ToolbarHelper::custom($task, $icon, \'\', ...)',
		'/onclick="checkAll\(/' => 'HTMLHelper::_(\'grid.checkall\') and the multiselect asset',
		'/application\.queue/' => '$app->getMessageQueue(true)',
		'/^class JFormRule/' => 'namespaced ...\\Rule\\XyzRule classes',
		'/->getQuery\(\s*true\s*\)/' => '->createQuery()',
	);

	/** the installer scripts, which have to return their InstallerScriptInterface */
	private function installerScripts()
	{
		$scripts = array(dirname(__DIR__, 2).'/updatescript.php', dirname(__DIR__, 2).'/package/script.php');
		if (getenv('COM_BFSTOP_ROOT'))
		{
			$scripts[] = getenv('COM_BFSTOP_ROOT').'/installscript.php';
		}
		return $scripts;
	}

	private function sources()
	{
		$roots = array(dirname(__DIR__, 2).'/src', dirname(__DIR__, 2).'/services');
		if (getenv('COM_BFSTOP_ROOT'))
		{
			foreach (array('admin', 'site') as $dir)
			{
				$roots[] = getenv('COM_BFSTOP_ROOT').'/'.$dir;
			}
		}
		$roots = array_merge($roots, $this->installerScripts());
		foreach ($roots as $root)
		{
			if (is_file($root))
			{
				yield $root;
				continue;
			}
			foreach (new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($root, \FilesystemIterator::SKIP_DOTS)) as $file)
			{
				// the vendored MaxMind reader is not ours to modernize
				if ($file->getExtension() === 'php' && strpos($file->getPathname(), '/Helper/Geo/') === false)
				{
					yield $file->getPathname();
				}
			}
		}
	}

	public function testNoDeprecatedApiIsUsed()
	{
		$found = array();
		$files = 0;
		foreach ($this->sources() as $path)
		{
			++$files;
			foreach (file($path) as $number => $line)
			{
				// comments may name the old forms
				if (preg_match('#^\s*(//|\*|/\*)#', $line))
				{
					continue;
				}
				foreach (self::Deprecated as $pattern => $replacement)
				{
					if (preg_match($pattern, $line))
					{
						$found[] = basename(dirname($path)).'/'.basename($path).':'.($number + 1).' use '.$replacement;
					}
				}
			}
		}
		// the plugin alone has about a dozen files (the unit tests run without
		// the component), with the component there are over fifty
		$this->assertGreaterThan(getenv('COM_BFSTOP_ROOT') ? 40 : 8, $files, 'the sources were not found');
		$this->assertSame(array(), $found, "deprecated API:\n".implode("\n", $found));
	}

	/**
	 * An installer script which returns no InstallerScriptInterface (only
	 * defines a class Joomla finds by its name) is deprecated, and won't work
	 * with Joomla! 7. The forms name the namespace of their rules: addrulepath
	 * only finds global JFormRule classes, a fallback of Joomla 3's.
	 */
	public function testInstallerScriptsAndFormsUseTheCurrentForms()
	{
		foreach ($this->installerScripts() as $script)
		{
			$this->assertMatchesRegularExpression('/\nreturn new \w+\(\);\s*$/', file_get_contents($script),
				basename($script).' has to return its InstallerScriptInterface');
		}
		$forms = array_merge(glob(dirname(__DIR__, 2).'/*.xml'),
			getenv('COM_BFSTOP_ROOT') ? glob(getenv('COM_BFSTOP_ROOT').'/admin/forms/*.xml') : array());
		foreach ($forms as $form)
		{
			$this->assertStringNotContainsString('addrulepath', file_get_contents($form), basename($form).': use addruleprefix');
		}
	}
}
