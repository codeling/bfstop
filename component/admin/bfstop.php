<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Access\Exception\NotAllowed;
use Joomla\CMS\Factory;
use Joomla\CMS\Language\Text;
use Joomla\CMS\MVC\Controller\BaseController;

$user = Factory::getApplication()->getIdentity();
if (!$user || !$user->authorise('core.manage', 'com_bfstop'))
{
	throw new NotAllowed(Text::_('JERROR_ALERTNOAUTHOR'), 403);
}

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/log.php');
require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/polyfill.php');
JLoader::register('BFStopToolbarHelper', dirname(__FILE__).'/helpers/toolbar.php');
$controller = BaseController::getInstance('bfstop');
$jinput = Factory::getApplication()->input;
$task = $jinput->get('task', "", 'STR');
$controller->execute($task);
$controller->redirect();
