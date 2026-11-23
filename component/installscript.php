<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\Installer\InstallerAdapter;
use Joomla\CMS\Installer\InstallerScript;
use Joomla\CMS\Installer\InstallerScriptInterface;
use Joomla\Database\DatabaseInterface;
use Joomla\Filesystem\Folder;
use Joomla\Registry\Registry;

/**
 * Joomla takes the instance this file returns (see the end); the class keeps
 * the name of the legacy form, which Joomla looks for if the file has been
 * loaded before. InstallerScript gives preflight() its checks.
 */
class com_bfstopInstallerScript extends InstallerScript implements InstallerScriptInterface
{
	// InstallerScript::preflight() refuses to install on anything older (and
	// to replace a newer version of the component with an older one)
	protected $minimumJoomla = '5.4.0';
	protected $minimumPhp = '8.2.0';

	// InstallerScript's checks, with the return type InstallerScriptInterface
	// has (InstallerScript's own preflight() has none)
	public function preflight($type, $adapter): bool
	{
		return (bool) parent::preflight($type, $adapter);
	}

	public function install(InstallerAdapter $adapter): bool
	{
		return true;
	}

	public function uninstall(InstallerAdapter $adapter): bool
	{
		self::unregisterFromActionLogs(Factory::getContainer()->get(DatabaseInterface::class));
		self::removePostInstallationMessage(Factory::getContainer()->get(DatabaseInterface::class));
		return true;
	}

	// the post-installation message which leads to the setup assistant
	public const PostInstallationTitle = 'COM_BFSTOP_POSTINSTALL_SETUP_TITLE';

	/**
	 * Adds the post-installation message which leads to the setup assistant
	 * (Joomla's Post-installation Messages, com_postinstall): shown while
	 * the setup isn't complete, see postinstall/setup.php. Written into the
	 * table as MessagesModel::addPostInstallationMessage() writes it: the
	 * model can't be used from the command line (it finds no table class
	 * there), and it can't add a message of type "link" (it drops the URL
	 * before it checks that there is one), so this is one of type "action".
	 * A message which is there already is replaced (and so shown again).
	 */
	public static function addPostInstallationMessage(DatabaseInterface $db): void
	{
		$element = 'com_bfstop';
		$query = $db->createQuery()
			->select($db->quoteName('extension_id'))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('type').' = '.$db->quote('component'))
			->where($db->quoteName('element').' = :element')
			->bind(':element', $element);
		$id = (int) $db->setQuery($query)->loadResult();
		if ($id < 1)
		{
			return;
		}
		$title = self::PostInstallationTitle;
		$db->setQuery($db->createQuery()
			->delete($db->quoteName('#__postinstall_messages'))
			->where($db->quoteName('extension_id').' = :id')
			->where($db->quoteName('title_key').' = :title')
			->bind(':id', $id, \Joomla\Database\ParameterType::INTEGER)
			->bind(':title', $title))->execute();
		$file = 'admin://components/com_bfstop/postinstall/setup.php';
		$row = (object) array(
			'extension_id' => $id,
			'title_key' => $title,
			'description_key' => 'COM_BFSTOP_POSTINSTALL_SETUP_DESC',
			'action_key' => 'COM_BFSTOP_POSTINSTALL_SETUP_ACTION',
			'language_extension' => 'com_bfstop',
			'language_client_id' => 1,
			'type' => 'action',
			'action_file' => $file,
			'action' => 'com_bfstop_postinstall_setup_action',
			'condition_file' => $file,
			'condition_method' => 'com_bfstop_postinstall_setup_condition',
			'version_introduced' => '2.0.0',
			'enabled' => 1,
		);
		$db->insertObject('#__postinstall_messages', $row);
	}

	/**
	 * Removes the post-installation messages of the component: Joomla
	 * doesn't when it uninstalls an extension.
	 */
	public static function removePostInstallationMessage(DatabaseInterface $db): void
	{
		try
		{
			$element = 'com_bfstop';
			$ids = $db->setQuery($db->createQuery()
				->select($db->quoteName('extension_id'))
				->from($db->quoteName('#__extensions'))
				->where($db->quoteName('type').' = '.$db->quote('component'))
				->where($db->quoteName('element').' = :element')
				->bind(':element', $element))->loadColumn();
			if (count($ids) === 0)
			{
				return;
			}
			$db->setQuery($db->createQuery()
				->delete($db->quoteName('#__postinstall_messages'))
				->whereIn($db->quoteName('extension_id'), array_map('intval', $ids)))->execute();
		}
		catch (\Throwable $e)
		{
			// nothing which should keep the component from being uninstalled
		}
	}

	// what the User Actions Log knows the component by (see ActionLogHelper)
	public const ActionLogExtension = 'com_bfstop';

	/**
	 * Makes the component one of the extensions the User Actions Log offers
	 * to record ("Events To Log" in its options), and - when it is new
	 * there - one it records: an extension added to the list later is not
	 * ticked otherwise. If an administrator unticks it, an update leaves that
	 * as it is.
	 *
	 * @return bool whether it was new to the list
	 */
	public static function registerWithActionLogs(DatabaseInterface $db): bool
	{
		$extension = self::ActionLogExtension;
		$query = $db->createQuery()
			->select('COUNT(*)')
			->from($db->quoteName('#__action_logs_extensions'))
			->where($db->quoteName('extension').' = :extension')
			->bind(':extension', $extension);
		if ((int) $db->setQuery($query)->loadResult() > 0)
		{
			return false;
		}
		$row = (object) array('extension' => $extension);
		$db->insertObject('#__action_logs_extensions', $row);
		self::changeLoggedExtensions($db, function (array $extensions) use ($extension)
		{
			return in_array($extension, $extensions, true) ? $extensions : array_merge($extensions, array($extension));
		});
		return true;
	}

	/**
	 * Takes the component out of the lists of the User Actions Log again.
	 * What it logged stays, as the entries of uninstalled extensions do.
	 */
	public static function unregisterFromActionLogs(DatabaseInterface $db): void
	{
		$extension = self::ActionLogExtension;
		try
		{
			$query = $db->createQuery()
				->delete($db->quoteName('#__action_logs_extensions'))
				->where($db->quoteName('extension').' = :extension')
				->bind(':extension', $extension);
			$db->setQuery($query)->execute();
			self::changeLoggedExtensions($db, function (array $extensions) use ($extension)
			{
				return array_values(array_diff($extensions, array($extension)));
			});
		}
		catch (\Throwable $e)
		{
			// nothing which should keep the component from being uninstalled
		}
	}

	/**
	 * Applies $change to the "loggable_extensions" option of com_actionlogs.
	 */
	private static function changeLoggedExtensions(DatabaseInterface $db, callable $change): void
	{
		$element = 'com_actionlogs';
		$query = $db->createQuery()
			->select($db->quoteName(array('extension_id', 'params')))
			->from($db->quoteName('#__extensions'))
			->where($db->quoteName('type').' = '.$db->quote('component'))
			->where($db->quoteName('element').' = :element')
			->bind(':element', $element);
		$component = $db->setQuery($query)->loadObject();
		if ($component === null)
		{
			return;
		}
		$params = new Registry((string) $component->params);
		$before = array_values(array_map('strval', (array) $params->get('loggable_extensions', array())));
		$after = $change($before);
		if ($after === $before)
		{
			return;
		}
		$params->set('loggable_extensions', $after);
		$json = $params->toString();
		$id = (int) $component->extension_id;
		$update = $db->createQuery()
			->update($db->quoteName('#__extensions'))
			->set($db->quoteName('params').' = :params')
			->where($db->quoteName('extension_id').' = :id')
			->bind(':params', $json)
			->bind(':id', $id, \Joomla\Database\ParameterType::INTEGER);
		$db->setQuery($update)->execute();
	}

	public function update(InstallerAdapter $adapter): bool
	{
		$bfstopPath = JPATH_ADMINISTRATOR."/components/com_bfstop/";
		$oldFolders = array( "views/whitelist", "views/whiteip" );
		// config.xml: the "Options" page (com_config) is gone since 2.0.0 - it
		// would save the component's params, which hold the settings, with
		// only its permissions; they are part of the settings page now
		$oldFiles = array( "models/whitelist.php", "models/whiteip.php", "config.xml" );
		foreach ($oldFolders as $folder)
		{
			if (file_exists($bfstopPath.$folder) && is_dir($bfstopPath.$folder))
			{
				Folder::delete($bfstopPath.$folder);
			}
		}
		foreach ($oldFiles as $file)
		{
			if (file_exists($bfstopPath.$file))
			{
				unlink($bfstopPath.$file);
			}
		}
		return true;
	}

	public function postflight(string $type, InstallerAdapter $adapter): bool
	{
		if ($type === 'install' || $type === 'update' || $type === 'discover_install')
		{
			try
			{
				self::registerWithActionLogs(Factory::getContainer()->get(DatabaseInterface::class));
			}
			catch (\Throwable $e)
			{
				// the component works without; the User Actions Log just lacks it
				Factory::getApplication()->enqueueMessage('Could not register with the User Actions Log: '.
					htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'), 'warning');
			}
		}
		if ($type === 'install' || $type === 'update' || $type === 'discover_install')
		{
			// what there is to do now - the setup assistant, which activates
			// the plugin - is said by the plugin's installer script; this
			// message stays in Joomla's Post-installation Messages until it
			// is done
			try
			{
				self::addPostInstallationMessage(Factory::getContainer()->get(DatabaseInterface::class));
			}
			catch (\Throwable $e)
			{
				Factory::getApplication()->enqueueMessage('Could not add the post-installation message: '.
					htmlspecialchars($e->getMessage(), ENT_QUOTES, 'UTF-8'), 'warning');
			}
		}
		return true;
	}
}

return new com_bfstopInstallerScript();
