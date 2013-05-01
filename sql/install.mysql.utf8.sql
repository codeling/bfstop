-- install script for bfstop plugin

CREATE TABLE IF NOT EXISTS #__bfstop_failedlogin (
	id int(10) NOT NULL auto_increment,
	username varchar(25) NOT NULL,
	ipaddress varchar(39) NOT NULL,
	error varchar(55) NOT NULL,
	logtime datetime NOT NULL,
	origin int NOT NULL,
	PRIMARY KEY  (id)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


CREATE TABLE IF NOT EXISTS #__bfstop_bannedip (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(39) NOT NULL,
	crdate datetime NOT NULL,
	PRIMARY KEY (id)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


-- create log for last successful to enable counter reset
CREATE TABLE IF NOT EXISTS #__bfstop_lastlogin (
	username varchar(25) NOT NULL,
	ipaddress varchar(39) NOT NULL,
	logtime datetime NOT NULL,
	PRIMARY KEY (username)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;


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
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

