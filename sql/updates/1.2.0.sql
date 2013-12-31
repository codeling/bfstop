-- allow white/blacklist ipaddress fields to also hold
-- subnet specifications
ALTER TABLE #__bfstop_bannedip MODIFY ipaddress VARCHAR(49) NOT NULL;
ALTER TABLE #__bfstop_whitelist MODIFY ipaddress VARCHAR(49) NOT NULL;

