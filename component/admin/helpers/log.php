<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Log\Log;
use Joomla\CMS\Plugin\PluginHelper;
use Joomla\Registry\Registry;

require_once(JPATH_SITE.'/plugins/system/bfstop/helpers/log.php');

function getLogger()
{
	$plugin = PluginHelper::getPlugin('system', 'bfstop');
	$params = new Registry($plugin->params);
	$loglevel = $params->get('logLevel', Log::ERROR);
	return new BFStopLogger($loglevel);
}
