-- for details on that table see install.mysql.utf8.sql

CREATE TABLE IF NOT EXISTS #__bfstop_lastlogin (
	username varchar(25) NOT NULL,
	ipaddress varchar(39) NOT NULL,
	logtime datetime NOT NULL,
	PRIMARY KEY  (username)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS #__bfstop_unblock (
	block_id int(10) NOT NULL,
	source int(10) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (block_id)
) DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS #__bfstop_unblock_token (
	token varchar(40) NOT NULL,
	block_id int(10) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (token)
) DEFAULT CHARSET=utf8;
