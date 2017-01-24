ALTER TABLE `#__bfstop_failedlogin` DROP COLUMN error;

ALTER TABLE `#__bfstop_whitelist` DROP COLUMN crdate;

ALTER TABLE `#__bfstop_whitelist` ADD COLUMN notes varchar(255) NOT NULL DEFAULT '';
