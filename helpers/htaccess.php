<?php
/*
 * @package Brute Force Stop (bfstop) for Joomla! >=2.5
 * @author Bernhard Froehler
 * @copyright (C) 2012-2014 Bernhard Froehler
 * @license GNU/GPLv3 http://www.gnu.org/licenses/gpl-3.0.html
**/
defined( '_JEXEC' ) or die;

/**
 .htaccess management class, based on the work by Jan-Paul Kleemans from
	 https://github.com/jpkleemans/Brute-Force-Login-Protection
 (licensed under GNU GENERAL PUBLIC LICENSE v2)
*/
class BFStopHtAccess
{
	/**
	 * Path to .htaccess file
	 * 
	 * @var string
	 */
	private $path;

	private $logger;


	/**
	 * Construct class with given $path.
	 * 
	 * @param string $dir
	 */
	public function __construct($dir, $logger)
	{
		$this->path = $dir . '/.htaccess';
		$this->logger = $logger;
	}

	public function getFileName() {
		return $this->path;
	}

	/**
	 * Get .htaccess lines before custom lines
	 * 
	 * @var array
	 */
	private function getHeader()
	{
		return array(
			'order allow,deny',
			'allow from all'
		);
	}

	/**
	 * Get .htaccess lines after custom lines
	 * 
	 * @var array
	 */
	private function getFooter()
	{
		return array(
		);
	}

	/**
	 * Check if .htaccess file is found, readable and writeable.
	 * 
	 * @return array
	 */
	public function checkRequirements()
	{
		$result = array(
			'apacheserver' => 
				strstr(strtolower(filter_var($_SERVER['SERVER_SOFTWARE'], FILTER_SANITIZE_STRING)), 'apache'),
			'found'		=> file_exists($this->path),
			'readable'	=> is_readable($this->path),
			'writeable'	=> is_writeable($this->path)
		);
		return $result;
	}

	/**
	 * Return array of denied IP addresses from .htaccess.
	 * 
	 * @return array
	 */
	public function getDeniedIPs()
	{
		$lines = $this->getLines('deny from ');

		foreach ($lines as $key => $line) {
			$lines[$key] = substr($line, 10);
		}

		return $lines;
	}

	/**
	 * Add 'deny from $IP' to .htaccess.
	 * 
	 * @param string $IP
	 * @return boolean
	 */
	public function denyIP($IP)
	{
		if (!filter_var($IP, FILTER_VALIDATE_IP)) return false;
		return $this->addLine('deny from ' . $IP);
	}

	/**
	 * Remove 'deny from $IP' from .htaccess.
	 * 
	 * @param string $IP
	 * @return boolean
	 */
	public function undenyIP($IP)
	{
		return $this->removeLine('deny from ' . $IP);
	}

	/**
	 * Edit ErrorDocument 403 line in .htaccess.
	 * 
	 * @param string $message
	 * @return boolean
	 */
	public function edit403Message($message)
	{
		if (empty($message)) return $this->remove403Message();

		$line = 'ErrorDocument 403 "' . $message . '"';

		$otherLines = $this->getLines('ErrorDocument 403 ', true, true);

		$insertion = array_merge($this->getHeader(), array($line), $otherLines, $this->getFooter());

		return $this->insert($insertion);
	}

	/**
	 * Remove ErrorDocument 403 line from .htaccess.
	 * 
	 * @return boolean
	 */
	public function remove403Message()
	{
		return $this->removeLine('', 'ErrorDocument 403 ');
	}

	/**
	 * Return array of (prefixed) lines from .htaccess.
	 * 
	 * @param string $prefixes
	 * @return array
	 */
	private function getLines($prefixes = false, $onlyBody = false, $exceptPrefix = false)
	{
		$allLines = $this->extract();

		if ($onlyBody) {
			$allLines = array_diff($allLines, $this->getHeader(), $this->getFooter());
		}

		if (!$prefixes) return $allLines;

		if (!is_array($prefixes)) {
			$prefixes = array($prefixes);
		}

		$prefixedLines = array();
		foreach ($allLines as $line) {
			foreach ($prefixes as $prefix) {
				if (strpos($line, $prefix) === 0) {
					$prefixedLines[] = $line;
				}
			}
		}

		if ($exceptPrefix) {
			$prefixedLines = array_diff($allLines, $prefixedLines);
		}

		return $prefixedLines;
	}

	/**
	 * Add single line to .htaccess.
	 * 
	 * @param string $line
	 * @return boolean
	 */
	private function addLine($line)
	{
		$insertion = array_merge($this->getHeader(), $this->getLines(false, true), array($line), $this->getFooter());

		return $this->insert(array_unique($insertion));
	}

	/**
	 * Remove single line from .htaccess.
	 * 
	 * @param string $line
	 * @param string $prefix
	 * @return boolean
	 */
	private function removeLine($line, $prefix = false)
	{
		$insertion = $this->getLines();

		if ($prefix !== false) {
			$lineKey = false;
			$prefixLength = strlen($prefix);
			foreach ($insertion as $key => $line) {
				if (substr($line, 0, $prefixLength) === $prefix) {
					$lineKey = $key;
					break;
				}
			}
		} else {
			$lineKey = array_search($line, $insertion);
		}

		if ($lineKey === false) return true;

		unset($insertion[$lineKey]);

		return $this->insert($insertion);
	}

	private static $marker = 'Brute Force Stop Blocks';

	/**
	 * Return array of strings from between BEGIN and END markers from .htaccess.
	 * 
	 * @return array Array of strings from between BEGIN and END markers from .htaccess.
	 */
	private function extract()
	{
		$result = array();

		if (!file_exists($this->path)) return $result;

		if ($markerdata = explode("\n", implode('', file($this->path)))) {
			$state = false;
			foreach ($markerdata as $markerline) {
				if (strpos($markerline, '# END ' . self::$marker) !== false) {
					$state = false;
				}
				if ($state) {
					$result[] = $markerline;
				}
				if (strpos($markerline, '# BEGIN ' . self::$marker) !== false) {
					$state = true;
				}
			}
		}

		return $result;
	}

	/**
	 * Insert an array of strings into .htaccess, placing it between BEGIN and END markers.
	 * Replace existing marked info. Retain surrounding data.
	 * Create file if none exists.
	 *
	 * @param string $insertion
	 * @return bool True on write success, false on failure.
	 */
	private function insert($insertion)
	{
		if (!file_exists($this->path) || is_writeable($this->path)) {
			if (!file_exists($this->path)) {
				$markerdata = '';
			} else {
				$markerdata = explode("\n", implode('', file($this->path)));
			}

			$newContent = '';

			$foundit = false;
			if ($markerdata) {
				$lineCount = count($markerdata);

				$state = true;
				foreach ($markerdata as $n => $markerline) {
					if (strpos($markerline, '# BEGIN ' . self::$marker) !== false) {
						$state = false;
					}

					if ($state) { // Non-BFLP lines
						if ($n + 1 < $lineCount) {
							$newContent .= "{$markerline}\n";
						} else {
							$newContent .= "{$markerline}";
						}
					}

					if (strpos($markerline, '# END ' . self::$marker) !== false) {
						$newContent .= "# BEGIN ".self::$marker."\n";
						if (is_array($insertion)) {
							foreach ($insertion as $insertline) {
								$newContent .= "{$insertline}\n";
							}
						}
						$newContent .= "# END ".self::$marker."\n";

						$state = true;
						$foundit = true;
					}
				}

				// If BEGIN marker found but missing END marker
				if ($state === false)
				{
					if (!is_null($this->logger))
					{
						$this->logger->log("corrupted .htaccess: BEGIN marker was found, but not END!", JLog::ERROR);
					}
					return false;
				}
			}

			if (!$foundit) {
				// insert at the very beginning:
				$beginContent = "# BEGIN ".self::$marker."\n";
				foreach ($insertion as $insertline) {
					$beginContent .= "{$insertline}\n";
				}
				$beginContent .= "# END ".self::$marker."\n\n";
				$newContent = $beginContent . $newContent;
			}

			return file_put_contents($this->path, $newContent, LOCK_EX);
		}
		if (!is_null($this->logger))
		{
			$this->logger->log(".htaccess file is not writable!", JLog::ERROR);
		}
		return false;
	}
}

