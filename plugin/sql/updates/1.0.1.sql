-- Update DB schema to version 1.0.1

-- fix ipaddress field lengths to enable holding all valid
-- representations of IPv6 addresses
ALTER TABLE #__bfstop_bannedip MODIFY ipaddress VARCHAR(45);
ALTER TABLE #__bfstop_failedlogin MODIFY ipaddress VARCHAR(45);

-- create table for whitelist:
CREATE TABLE IF NOT EXISTS #__bfstop_whitelist (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (id)
) DEFAULT CHARSET=utf8;

