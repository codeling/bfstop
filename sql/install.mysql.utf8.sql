-- install script for bfstop plugin

CREATE TABLE IF NOT EXISTS #__bfstop_failedlogin (
	id int(10) NOT NULL auto_increment,
	username varchar(25) NOT NULL,
	ipaddress varchar(45) NOT NULL,
	error varchar(255) NOT NULL,
	logtime datetime NOT NULL,
	origin int NOT NULL,
	handled BOOLEAN NOT NULL DEFAULT 0,
	PRIMARY KEY  (id)
) DEFAULT CHARSET=utf8;


CREATE TABLE IF NOT EXISTS #__bfstop_bannedip (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	crdate datetime NOT NULL,
	duration int NOT NULL,
	PRIMARY KEY (id)
) DEFAULT CHARSET=utf8;


-- stores a new entry if an IP address was unblocked, the
-- time and by which means that unblocking happened
CREATE TABLE IF NOT EXISTS #__bfstop_unblock (
-- which block was lifted (references id column from bannedip table)
	block_id int(10) NOT NULL,
-- the source from which the unblock resulted:
--	0 .. via the backend
--      1 .. via the mail sent to the user after blocking
	source int(10) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (block_id)
) DEFAULT CHARSET=utf8;


-- stores randomized tokens for unblocking an IP via an email
-- to the blocked user
CREATE TABLE IF NOT EXISTS #__bfstop_unblock_token (
	token varchar(40) NOT NULL,
	block_id int(10) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (token)
) DEFAULT CHARSET=utf8;


-- stores a whitelist of IPs which will never be blocked
CREATE TABLE IF NOT EXISTS #__bfstop_whitelist (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (id)
) DEFAULT CHARSET=utf8;
