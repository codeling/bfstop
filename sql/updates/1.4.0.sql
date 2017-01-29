ALTER TABLE `#__bfstop_failedlogin` DROP COLUMN error;


ALTER TABLE `#__bfstop_whitelist` ADD COLUMN notes varchar(255) NOT NULL DEFAULT '';

UPDATE `#__bfstop_whitelist` SET notes=CONCAT('created: ',DATE_FORMAT(crdate, '%Y-%m-%d')) WHERE crdate != '0000-00-00 00:00:00';

ALTER TABLE `#__bfstop_whitelist` DROP COLUMN crdate;
