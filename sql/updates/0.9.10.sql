-- create new successfuly login log to enable counter reset
CREATE TABLE IF NOT EXISTS #__bfstop_lastlogin (
	username varchar(25) NOT NULL,
	ipaddress varchar(39) NOT NULL,
	logtime datetime NOT NULL,
	PRIMARY KEY  (username)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
