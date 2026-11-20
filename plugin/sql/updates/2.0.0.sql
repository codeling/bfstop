-- Update DB schema to version 2.0.0

-- If an update stops halfway (e.g. a timeout converting a large table), the
-- schema version stays at the previous one, and the next attempt runs this
-- file again from the start: every statement has to work on tables which
-- already have its change. Statements which can't be written that way in
-- MySQL (ADD COLUMN, ADD INDEX) are marked "CAN FAIL" for Joomla's installer
-- (Joomla 4.2+), which then goes on if they fail. Checked by
-- tests/Unit/UpdateSqlTest.php and tests/Integration/UpdateSqlTest.php.

-- number of requests rejected because of a block, and the time of the
-- latest one (issue #219); existing blocks start with no data
ALTER TABLE `#__bfstop_bannedip` ADD COLUMN attempts int unsigned NOT NULL DEFAULT 0 /** CAN FAIL **/;

ALTER TABLE `#__bfstop_bannedip` ADD COLUMN last_attempt datetime NULL DEFAULT NULL /** CAN FAIL **/;


-- use utf8mb4 like Joomla's own tables; with utf8 (3-byte), a failed login
-- for a username containing e.g. an emoji could not be stored at all
ALTER TABLE `#__bfstop_failedlogin` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_bannedip` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_unblock` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

ALTER TABLE `#__bfstop_unblock_token` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- the user an unblock link was sent to, to limit the links per user
ALTER TABLE `#__bfstop_unblock_token` ADD COLUMN username varchar(150) NULL DEFAULT NULL /** CAN FAIL **/;

-- the same in lower case, computed by the database, for lookups by user name
-- which don't tell "Bob" from "bob" (see install.mysql.utf8.sql)
ALTER TABLE `#__bfstop_unblock_token` ADD COLUMN username_lc varchar(150) GENERATED ALWAYS AS (LOWER(username)) STORED /** CAN FAIL **/;

ALTER TABLE `#__bfstop_unblock_token` ADD KEY username_lc (username_lc) /** CAN FAIL **/;

ALTER TABLE `#__bfstop_allowlist` CONVERT TO CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- tables introduced in 2.0.0, see install.mysql.utf8.sql for details
CREATE TABLE IF NOT EXISTS `#__bfstop_knownip` (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	username varchar(150) NOT NULL,
	first_success datetime NOT NULL,
	last_success datetime NOT NULL,
	username_lc varchar(150) GENERATED ALWAYS AS (LOWER(username)) STORED,
	PRIMARY KEY (id),
	UNIQUE KEY ip_username (ipaddress, username),
	KEY username_lc (username_lc)
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
ALTER TABLE `#__bfstop_failedlogin` ADD INDEX username_logtime (username, logtime) /** CAN FAIL **/;
-- the failed logins of an address within a time span (counted for every
-- failed login), and those of the last hour / older than the purge age
ALTER TABLE `#__bfstop_failedlogin` ADD INDEX ipaddress_logtime (ipaddress, logtime) /** CAN FAIL **/;
ALTER TABLE `#__bfstop_failedlogin` ADD INDEX logtime (logtime) /** CAN FAIL **/;

-- every request looks up the visitor's address in the block and allow list;
-- addresses and networks are stored in canonical form (the plugin brings
-- existing entries into it once, IpHelper::canonicalEntry())
ALTER TABLE `#__bfstop_bannedip` ADD INDEX ipaddress (ipaddress) /** CAN FAIL **/;
ALTER TABLE `#__bfstop_allowlist` ADD INDEX ipaddress (ipaddress) /** CAN FAIL **/;

-- what the purge of old blocks keeps of them (issue #283, C14), see
-- install.mysql.utf8.sql; blocks purged by earlier versions are gone
CREATE TABLE IF NOT EXISTS `#__bfstop_offence` (
	ipaddress varchar(49) NOT NULL,
	blocks int unsigned NOT NULL DEFAULT 0,
	last_block datetime NOT NULL,
	PRIMARY KEY (ipaddress),
	KEY last_block (last_block)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;

-- the plugin's own bookkeeping (name => value), apart from its settings: when
-- the maintenance last ran. In the plugin's row of #__extensions, it was
-- written by requests with the whole settings, and so raced with an
-- administrator saving them.
CREATE TABLE IF NOT EXISTS `#__bfstop_state` (
	name varchar(64) NOT NULL,
	value varchar(255) NOT NULL,
	changed datetime NOT NULL,
	PRIMARY KEY (name)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;
