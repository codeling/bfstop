-- Update DB schema to version 2.0.0

-- number of requests rejected because of a block, and the time of the
-- latest one (issue #219); existing blocks start with no data
ALTER TABLE `#__bfstop_bannedip` ADD COLUMN attempts int unsigned NOT NULL DEFAULT 0;

ALTER TABLE `#__bfstop_bannedip` ADD COLUMN last_attempt datetime NULL DEFAULT NULL;


-- use utf8mb4 like Joomla's own tables; with utf8 (3-byte), a failed login
-- for a username containing e.g. an emoji could not be stored at all
ALTER TABLE `#__bfstop_failedlogin` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_bannedip` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_unblock` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_unblock_token` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_allowlist` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- tables introduced in 2.0.0, see install.mysql.utf8.sql for details
CREATE TABLE IF NOT EXISTS `#__bfstop_knownip` (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	username varchar(150) NOT NULL,
	first_success datetime NOT NULL,
	last_success datetime NOT NULL,
	PRIMARY KEY (id),
	UNIQUE KEY ip_username (ipaddress, username)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS `#__bfstop_dnscache` (
	ipaddress varchar(45) NOT NULL,
	hostname varchar(255) DEFAULT NULL,
	checked_at datetime NOT NULL,
	PRIMARY KEY (ipaddress)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- per-username failed login statistics (issue #136)
CREATE TABLE IF NOT EXISTS `#__bfstop_username_stats` (
	username varchar(150) NOT NULL,
	attempts int unsigned NOT NULL DEFAULT 0,
	first_attempt datetime NOT NULL,
	last_attempt datetime NOT NULL,
	PRIMARY KEY (username),
	KEY attempts (attempts),
	KEY last_attempt (last_attempt)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;

-- seed the statistics from the failed login entries still retained
INSERT INTO `#__bfstop_username_stats` (username, attempts, first_attempt, last_attempt)
	SELECT username, COUNT(*), MIN(logtime), MAX(logtime)
	FROM `#__bfstop_failedlogin` GROUP BY username
	ON DUPLICATE KEY UPDATE attempts=attempts;

-- speeds up the per-username (account-level) throttle query
ALTER TABLE `#__bfstop_failedlogin` ADD INDEX username_logtime (username, logtime);
