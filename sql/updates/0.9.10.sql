-- for details on that table see install.mysql.utf8.sql

ALTER TABLE `#__bfstop_failedlogin`
	ADD COLUMN handled BOOLEAN NOT NULL DEFAULT 0
;

CREATE TABLE IF NOT EXISTS `#__bfstop_unblock` (
	block_id int(10) NOT NULL,
	source int(10) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (block_id)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__bfstop_unblock_token` (
	token varchar(40) NOT NULL,
	block_id int(10) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (token)
) DEFAULT CHARSET=utf8;
