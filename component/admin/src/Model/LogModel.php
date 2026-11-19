<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/

namespace Codeling\Component\Bfstop\Administrator\Model;

defined('_JEXEC') or die;

use Codeling\Library\Bfstop\Helper\LoggerHelper;
use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\ListModel;

/**
 * The entries of the log, newest first unless the list is ordered the other
 * way: those of the log file and of its previous generation (see
 * LoggerHelper::getLogFiles()). The files are read once per request; the
 * entries of a page are only parsed when it is asked for.
 */
class LogModel extends ListModel
{
	/** @var string[]|null the lines of the entries, oldest first */
	private ?array $lines = null;

	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			'date', 'priority'
		);
		parent::__construct($config);
	}

	/**
	 * The lines of the entries of both generations, oldest first: the
	 * previous generation holds what the log file had before it was rotated.
	 * Lines starting with # are the file's header (Joomla's file formatter
	 * writes six of them, the first is what keeps the file from being read
	 * through the web server).
	 *
	 * @return string[]
	 */
	private function getLines()
	{
		if ($this->lines !== null)
		{
			return $this->lines;
		}
		$this->lines = array();
		foreach (array_reverse(LoggerHelper::getLogFiles()) as $path)
		{
			$fileLines = is_file($path) ? @file($path, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) : false;
			foreach ($fileLines ?: array() as $line)
			{
				if ($line[0] !== '#')
				{
					$this->lines[] = $line;
				}
			}
		}
		return $this->lines;
	}

	private function parseLine($line)
	{
		$logItems = explode(" ", $line);
		if (count($logItems) < 3)
		{
			Factory::getApplication()->enqueueMessage("Invalid entry: '".htmlspecialchars($line, ENT_QUOTES, 'UTF-8')."' (expected 3 items - date, priority and message but that line only has ".count($logItems).")", 'error');
			return null;
		}
		$logLineObj = new \stdClass();
		$logLineObj->date = $logItems[0];
		$logLineObj->priority = $logItems[1];
		$logLineObj->message = implode(" ", array_slice($logItems, 2));
		return $logLineObj;
	}

	public function getItems()
	{
		$lines = $this->getLines();
		$ordering = $this->getState('list.ordering', 'date');
		$descending = strtoupper((string) $this->getState('list.direction', 'DESC')) !== 'ASC';
		$count = (int) $this->getState('list.limit');
		$start = (int) $this->getStart();
		if ($ordering === 'priority')
		{
			// the order needs every entry
			$entries = array_filter(array_map(array($this, 'parseLine'), $lines));
			// the sort is stable: entries of the same priority stay in the order of the file
			usort($entries, fn ($a, $b) => strcmp($a->priority, $b->priority));
			if ($descending)
			{
				$entries = array_reverse($entries);
			}
			return array_slice($entries, $start, $count > 0 ? $count : null);
		}
		// by date, which is the order of the file
		if ($descending)
		{
			$lines = array_reverse($lines);
		}
		$page = array_slice($lines, $start, $count > 0 ? $count : null);
		return array_values(array_filter(array_map(array($this, 'parseLine'), $page)));
	}

	protected function populateState($ordering = null, $direction = null)
	{
		parent::populateState('date', 'DESC');
	}

	public function getTotal()
	{
		return count($this->getLines());
	}
}
