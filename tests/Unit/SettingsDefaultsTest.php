<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
namespace Codeling\Bfstop\Tests\Unit;

use Codeling\Library\Bfstop\Origin;
use Codeling\Library\Bfstop\Settings;
use PHPUnit\Framework\TestCase;

/**
 * The defaults of the settings are in one place, Settings::Defaults: the
 * settings page shows the same, and no code reads a setting with a default
 * of its own (which could differ from it, unnoticed).
 */
class SettingsDefaultsTest extends TestCase
{
	/** @return array<string, string> name => default of every field of the settings page */
	private static function formDefaults(): array
	{
		$xml = simplexml_load_file(BFSTOP_COMPONENT_ROOT.'/admin/forms/settings.xml');
		$defaults = array();
		foreach ($xml->xpath('//fields[@name="params"]//field') as $field)
		{
			$defaults[(string) $field['name']] = (string) $field['default'];
		}
		return $defaults;
	}

	public function testEverySettingHasItsDefaultAndOnlyThose()
	{
		$form = self::formDefaults();
		// the page was found and read: it has 50 settings (2.0.0)
		$this->assertGreaterThan(40, count($form));
		$this->assertSame(array(), array_values(array_diff(array_keys($form), array_keys(Settings::Defaults))),
			'settings without a default in Settings::Defaults');
		$this->assertSame(array(), array_values(array_diff(array_keys(Settings::Defaults), array_keys($form))),
			'defaults of settings the page hasn\'t got');
		foreach (Settings::Defaults as $name => $default)
		{
			if ($name === 'enabledForOrigin')
			{
				$this->assertSame($default, Origin::mask(explode(',', $form[$name])), $name);
				continue;
			}
			$this->assertSame((string) $default, $form[$name], $name);
		}
	}

	public function testNoCodeReadsASettingWithADefaultOfItsOwn()
	{
		$names = implode('|', array_keys(Settings::Defaults));
		$files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator(dirname(__DIR__, 2),
			\FilesystemIterator::SKIP_DOTS));
		$found = array();
		foreach ($files as $file)
		{
			$path = $file->getPathname();
			if ($file->getExtension() !== 'php' || preg_match('#/(vendor|tests|\.git)/#', $path) ||
				str_ends_with($path, '/updatescript.php'))
			{
				continue;
			}
			// ->get('blockMode', 'full'), ParamHelper::get('x', ...), intParam('x', 5), ...
			if (preg_match_all("/(?:->get|::get|Param)\(\s*'(?:$names)'\s*,/", file_get_contents($path), $m))
			{
				$found[] = str_replace(dirname(__DIR__, 2).'/', '', $path).': '.implode(', ', $m[0]);
			}
		}
		$this->assertSame(array(), $found, 'read with Settings::get()/int()/bool()/string() instead');
	}
}
