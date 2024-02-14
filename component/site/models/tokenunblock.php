<?php
/*
 * @package BFStop Component (com_bfstop) for Joomla!
 * @author Bernhard Froehler
 * @copyright (C) Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined('_JEXEC') or die;

use Joomla\CMS\Log\Log;
use Joomla\CMS\MVC\Model\BaseDatabaseModel;

require_once(JPATH_ADMINISTRATOR.'/components/com_bfstop/helpers/unblock.php');

class BFStopModelTokenUnblock extends BaseDatabaseModel {

	const TokenValidDays = 3;

	public function unblock($token, $logger) {
		// prune old tokens:
		try {
			$this->_db->setQuery('DELETE FROM #__bfstop_unblock_token '.
				'WHERE DATE_ADD(crdate, INTERVAL '.self::TokenValidDays.' DAY) < '.
				$this->_db->quote(date('Y-m-d H:i:s')));
			$this->_db->execute();
			// get token:
			$this->_db->setQuery('SELECT * FROM #__bfstop_unblock_token WHERE token='.
				$this->_db->quote($token));
			$unblockTokenEntry = $this->_db->loadObject();
			if ($unblockTokenEntry == null) {
				$logger->log("com_bfstop-tokenunblock: Token not found.", Log::ERROR);
				return false;
			}
			BFStopUnblockHelper::unblockDB($this->_db, array($unblockTokenEntry->block_id), 1, $logger);
			$sql = 'DELETE FROM #__bfstop_unblock_token WHERE token='.
					$this->_db->quote($token);
			$this->_db->setQuery($sql);
			$success = $this->_db->execute();
		}
		catch (RuntimeException $e)
		{
			$sucess = false;
			$logger->log($e->getMessage(), Log::ERROR);
		}
		if (!$success) {
			$logger->log("com_bfstop-tokenunblock: Could not delete unblock_token.", Log::ERROR);
		} else  {
			$logger->log("com_bfstop-tokenunblock: Successfully unblocked with token.", Log::INFO);
		}
		return $success;
	}
}
