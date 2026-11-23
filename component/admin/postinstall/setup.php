<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Repository\Repositories;
use Codeling\Library\Bfstop\Service\Setup\SetupState;
use Codeling\Component\Bfstop\Administrator\Helper\LogHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\Router\Route;

/**
 * The post-installation message of Brute Force Stop (see the component's
 * installer script): shown while the setup assistant hasn't been completed.
 * Joomla's Post-installation Messages call plain functions of a file.
 */
function com_bfstop_postinstall_setup_condition()
{
	if (!class_exists(SetupState::class))
	{
		// without the library there is nothing to set up
		return false;
	}
	return !SetupState::load((new Repositories(LogHelper::getLogger()))->state())->isCompleted();
}

/** The action of the message: opens the setup assistant. */
function com_bfstop_postinstall_setup_action()
{
	Factory::getApplication()->redirect(Route::_('index.php?option=com_bfstop&view=setup', false));
}
