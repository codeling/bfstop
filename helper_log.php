<?php
defined('_JEXEC') or die;

class BFStopLogger {

        private $enabled;
        private static $logCategory = 'bfstop';

        function __construct($enabled)
        {
                $this->enabled = $enabled;
                if ($enabled)
                {
                        JLog::addLogger(array(
                                'text_file' => 'plg_system_bfstop.log.php'
                        ), JLog::ALL,
                        self::$logCategory);
                }

        }
        function isEnabled() {
                return $this->enabled;
        }


        function log($msg, $priority)
        {
                if ($this->isEnabled())
                {
                        JLog::add($msg, $priority, self::$logCategory);
                }
        }
}

