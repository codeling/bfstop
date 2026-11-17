ALTER TABLE #__bfstop_failedlogin MODIFY error VARCHAR(255);

ALTER TABLE #__bfstop_bannedip ADD duration int NOT NULL DEFAULT 0;
