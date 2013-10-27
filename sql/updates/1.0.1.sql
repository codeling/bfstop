-- fix ipaddress field lengths to enable holding all valid
-- representations of IPv6 addresses

ALTER TABLE #__bfstop_bannedip MODIFY ipaddress VARCHAR(45);
ALTER TABLE #__bfstop_failedlogin MODIFY ipaddress VARCHAR(45);

