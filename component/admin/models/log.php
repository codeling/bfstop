<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Factory;
use Joomla\CMS\MVC\Model\ListModel;

const HeaderLines = 6;

class BFStopModelLog extends ListModel
{
	public function __construct($config = array())
	{
		$config['filter_fields'] = array(
			'date', 'priority'
		);
		parent::__construct($config);
	}

	private function getLogFilePath()
	{
		$application = Factory::getApplication();
		$log_path = $application->getCfg('log_path');
		return $log_path."/plg_system_bfstop.log.php";
	}

	private function getLogLines($start, $count, $ordering, $direction)
	{	// $direction currently unused
		$logLines = array();
		$logfile = @fopen($this->getLogFilePath(), 'r');
		if ($logfile === FALSE)
		{
			return $logLines;
		}
		$lineNumber = 0;
		while (($line = fgets($logfile)) !== false &&
			($count === 0 || ($lineNumber < (HeaderLines + $start + $count))))
		{
			if ($lineNumber >= HeaderLines + $start)
			{
				$logItems = explode(" ", $line);
				if (count($logItems) < 3)
				{
					$application->enqueueMessage("Invalid log line: ".$line, 'error');
				}
				else
				{
					$logLineObj = new stdClass();
					$logLineObj->date = $logItems[0];
					$logLineObj->priority = $logItems[1];
					$logLineObj->message = implode(" ", array_slice($logItems, 2, count($logItems)-2));
					$logLines[] = $logLineObj;
				}
			}
			$lineNumber++;
		}
		fclose($logfile);
		return $logLines;
	}

	public function getItems()
	{
		$start = $this->getStart();
		$count = $this->getState('list.limit');
		$ordering  = $this->getState('list.ordering', 'date');
		$direction = $this->getState('list.direction', 'desc'); // currently unused
		$result = $this->getLogLines($start, $count, $ordering, $direction);
		return $result;
	}

	protected function populateState($ordering = null, $direction = null)
	{	// currently unused, no sort functionality at the moment
		parent::populateState('date', 'DESC');
	}

	public function getTotal()
	{
		try
		{
			$file = new \SplFileObject($this->getLogFilePath(), 'r');
			$file->seek(PHP_INT_MAX);
			return ($file->key()-HeaderLines + 1);
		}
		catch (RuntimeException $e)
		{
			return 0;
		}
	}
}
