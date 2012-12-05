-- install script for bfstop plugin

CREATE TABLE IF NOT EXISTS #__bfstop_failedlogin (
	id int(10) NOT NULL auto_increment,
	username varchar(25) NOT NULL,
	password varchar(25) NOT NULL,
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

