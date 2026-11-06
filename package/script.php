<?php
/*
 * @package BFStop Package (pkg_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Installer\InstallerScript;

/**
 * Runs before the plugin and the component are installed: InstallerScript's
 * preflight() refuses Joomla and PHP versions BFStop 2 doesn't run on (a site
 * on Joomla 4 has to stay with BFStop 1.5), before anything is changed.
 * Plugin and component check the same themselves when they are installed
 * on their own.
 */
class pkg_bfstopInstallerScript extends InstallerScript
{
	protected $minimumJoomla = '5.0.0';
	protected $minimumPhp = '8.1.0';
}
