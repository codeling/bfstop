-- Update DB schema to version 2.0.0

-- number of requests rejected because of a block, and the time of the
-- latest one (issue #219); existing blocks start with no data
ALTER TABLE `#__bfstop_bannedip` ADD COLUMN attempts int unsigned NOT NULL DEFAULT 0;

ALTER TABLE `#__bfstop_bannedip` ADD COLUMN last_attempt datetime NULL DEFAULT NULL;


-- tables introduced in 2.0.0, see install.mysql.utf8.sql for details
CREATE TABLE IF NOT EXISTS `#__bfstop_knownip` (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	username varchar(150) NOT NULL,
	first_success datetime NOT NULL,
	last_success datetime NOT NULL,
	PRIMARY KEY (id),
	UNIQUE KEY ip_username (ipaddress, username)
) DEFAULT CHARSET=utf8;


CREATE TABLE IF NOT EXISTS `#__bfstop_dnscache` (
	ipaddress varchar(45) NOT NULL,
	hostname varchar(255) DEFAULT NULL,
	checked_at datetime NOT NULL,
	PRIMARY KEY (ipaddress)
) DEFAULT CHARSET=utf8;
