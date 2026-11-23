<?php
/*
 * @package BFStop Console Plugin (plg_console_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\Console\Bfstop\Command;

defined('_JEXEC') or die;

use Codeling\Component\Bfstop\Administrator\Model\SetupModel;
use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Settings;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Factory\MVCFactoryServiceInterface;
use Joomla\Console\Command\AbstractCommand;

/**
 * What the commands of Brute Force Stop share. The settings are saved, and
 * protection activated, by the setup assistant's model of the component
 * (booted through Joomla, as it is in the backend): the same checks and the
 * same records as in the browser.
 */
abstract class BfstopCommand extends AbstractCommand
{
	/** The languages of the component and the plugin, whose strings the model's messages are. */
	protected function loadLanguage(): void
	{
		$language = Factory::getApplication()->getLanguage();
		$language->load('com_bfstop', JPATH_ADMINISTRATOR) || $language->load('com_bfstop', JPATH_ADMINISTRATOR.'/components/com_bfstop');
		$language->load('plg_system_bfstop.sys', JPATH_ADMINISTRATOR) ||
			$language->load('plg_system_bfstop.sys', JPATH_PLUGINS.'/system/bfstop');
	}

	/** The setup assistant's model, null without the component. */
	protected function setupModel(): ?SetupModel
	{
		try
		{
			$component = Factory::getApplication()->bootComponent('com_bfstop');
		}
		catch (\Throwable $e)
		{
			return null;
		}
		if (!$component instanceof MVCFactoryServiceInterface)
		{
			return null;
		}
		$model = $component->getMVCFactory()->createModel('Setup', 'Administrator', array('ignore_request' => true));
		return $model instanceof SetupModel ? $model : null;
	}

	protected static function repositories(): Repositories
	{
		return new Repositories(LoggerHelper::fromSettings(Settings::stored()));
	}

	/** The errors of $model as one message, without markup (the console shows it as it is). */
	protected static function errors(SetupModel $model): string
	{
		$errors = array_map(fn ($error) => $error instanceof \Throwable ? $error->getMessage() : (string) $error, $model->getErrors());
		return html_entity_decode(strip_tags(implode("\n", $errors)), ENT_QUOTES, 'UTF-8');
	}

	/** A language string without markup. */
	protected static function plain(string $text): string
	{
		return html_entity_decode(strip_tags($text), ENT_QUOTES, 'UTF-8');
	}
}
