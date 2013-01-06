<?php // no direct access
defined('_JEXEC') or die('Restricted access');

class plgsystembfstopInstallerScript
{

	static function loadLanguage()
	{
		$lang =& JFactory::getLanguage();
		$lang->load('plg_system_bfstop', JPATH_ADMINISTRATOR);
		$lang->load('plg_system_bfstop.sys', JPATH_ADMINISTRATOR);
		$lang->load('plg_bfstop', JPATH_ADMINISTRATOR);
		$lang->load('plg_bfstop.sys', JPATH_ADMINISTRATOR);
		$lang->load('plg_system_bfstop', JPATH_BASE);
		$lang->load('plg_system_bfstop.sys', JPATH_BASE);
		$lang->load('plg_bfstop', JPATH_BASE);
		$lang->load('plg_bfstop.sys', JPATH_BASE);
	
/*
		JPlugin::loadLanguage('plg_system_bfstop');
		JPlugin::loadLanguage('plg_system_bfstop.sys');
		JPlugin::loadLanguage('plg_bfstop.sys');
		JPlugin::loadLanguage('plg_bfstop');
*/
	}
	function install($parent)
	{
	}
	function uninstall($parent)
	{
		self::loadLanguage();
		echo JText::_('PLG_BFSTOP_UNINSTALL_TEXT');
	}
	function update($parent)
	{
		self::loadLanguage();
		echo JText::_('PLG_BFSTOP_UPDATE_TEXT');
	}

	function preflight($type, $parent) {}
	function postflight($type, $parent)
	{
		self::loadLanguage();
		echo JText::_('PLG_BFSTOP_INSTALL_TEXT');
	}
}
