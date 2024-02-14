<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

function bfstopBuildRoute(&$query)
{
	$segments = array();
/*
	if (isset($query['view']))
	{
		$segments[] = $query['view'];
		unset($query['view']);
		if (isset($query['token']))
		{
			$segments[] = $query['token'];
			unset($query['token']);
		}
	}
*/
	return $segments;
}

function bfstopParseRoute($segments)
{
	$vars = array();
/*
	switch ($segments[0])
	{
		case 'tokenunblock':
			$vars['view'] = 'tokenunblock';
			$vars['token'] = count($segments) > 1 ? $segments[1] : "";
			break;
		default:
			$vars['view'] = 'tokenunblock';
	}
*/
	return $vars;
}
