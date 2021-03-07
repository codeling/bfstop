DELETE FROM #__update_sites WHERE location LIKE 'https://github.com/codeling%';

ALTER TABLE #__bfstop_failedlogin MODIFY username varchar(150) NOT NULL;
