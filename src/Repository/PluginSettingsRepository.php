<?php
/*
 * @package BFStop Plugin (bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Plugin\System\Bfstop\Repository;

defined('_JEXEC') or die;

use Joomla\CMS\Cache\CacheControllerFactoryInterface;
use Joomla\CMS\Factory;

/**
 * The plugin's settings, as stored in its row of #__extensions. Also holds
 * the plugin's bookkeeping (when the maintenance last ran), which isn't set
 * on the settings page.
 */
class PluginSettingsRepository extends Repository
{
	/**
	 * $query, limited to the plugin's row; $values gets the parameters.
	 */
	private function pluginRow($query, array &$values)
	{
		$values = array('type' => 'plugin', 'folder' => 'system', 'element' => 'bfstop');
		return $query->where($this->db->quoteName('type').' = :type')
			->where($this->db->quoteName('folder').' = :folder')
			->where($this->db->quoteName('element').' = :element');
	}

	/** the stored settings (the JSON of the params column) */
	private function storedParams()
	{
		$values = array();
		$query = $this->pluginRow($this->db->createQuery()
			->select($this->db->quoteName('params'))
			->from($this->db->quoteName('#__extensions')), $values);
		return json_decode((string) $this->scalar($query, $values), true);
	}

	/**
	 * A setting as it is stored now - the plugin's $params are what was
	 * stored when the request began.
	 *
	 * Fail-open: $default.
	 */
	public function get($name, $default = null)
	{
		return $this->failOpen('get', function () use ($name, $default)
		{
			$params = $this->storedParams();
			return (is_array($params) && array_key_exists($name, $params)) ? $params[$name] : $default;
		}, $default);
	}

	/**
	 * Stores one value in the plugin's settings.
	 *
	 * Only this one value is changed in the plugin's stored settings, which
	 * are read from the database right now: writing back the settings the
	 * request was started with would undo whatever an administrator saved in
	 * the meantime.
	 *
	 * Fail-open: not stored (the bookkeeping is redone).
	 */
	public function set($name, $value)
	{
		$this->failOpen('set', function () use ($name, $value)
		{
			$params = $this->storedParams();
			if (!is_array($params))
			{
				$params = array();
			}
			$params[$name] = $value;
			// no table alias here: PostgreSQL doesn't allow qualified column
			// names in the SET clause (issue #206)
			$values = array();
			$query = $this->pluginRow($this->db->createQuery()
				->update($this->db->quoteName('#__extensions'))
				->set($this->db->quoteName('params').' = :params'), $values);
			$values['params'] = json_encode($params);
			$this->execute($query, $values);
			// the plugin list (with the settings) is cached
			Factory::getContainer()->get(CacheControllerFactoryInterface::class)
				->createCacheController('callback', array('defaultgroup' => 'com_plugins'))
				->clean();
		}, null);
	}
}
