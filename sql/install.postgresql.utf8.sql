-- install script for bfstop plugin, PostgreSQL version (issue #206);
-- see install.mysql.utf8.sql for a description of the tables. Keep both in sync!
--
-- differences to the MySQL schema:
--  - handled is a smallint, not a BOOLEAN: the code compares it with 0/1,
--    which PostgreSQL doesn't allow for boolean columns
--  - no unsigned integer types in PostgreSQL
--  - ipaddress in bannedip and allowlist is varchar(49) (as for MySQL
--    installs updated via 1.2.0.sql), to hold IPv6 subnets like
--    "ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255/128"

CREATE TABLE IF NOT EXISTS "#__bfstop_failedlogin" (
  "id" serial NOT NULL,
  "username" varchar(150) NOT NULL,
  "ipaddress" varchar(45) NOT NULL,
  "logtime" timestamp without time zone NOT NULL,
  "origin" integer NOT NULL,
  "handled" smallint NOT NULL DEFAULT 0,
  PRIMARY KEY ("id")
);


CREATE TABLE IF NOT EXISTS "#__bfstop_bannedip" (
  "id" serial NOT NULL,
  "ipaddress" varchar(49) NOT NULL,
  "crdate" timestamp without time zone NOT NULL,
  "duration" integer NOT NULL,
  "attempts" integer NOT NULL DEFAULT 0,
  "last_attempt" timestamp without time zone DEFAULT NULL,
  PRIMARY KEY ("id")
);


CREATE TABLE IF NOT EXISTS "#__bfstop_unblock" (
  "block_id" integer NOT NULL,
  "source" integer NOT NULL,
  "crdate" timestamp without time zone NOT NULL,
  PRIMARY KEY ("block_id")
);


CREATE TABLE IF NOT EXISTS "#__bfstop_unblock_token" (
  "token" varchar(40) NOT NULL,
  "block_id" integer NOT NULL,
  "crdate" timestamp without time zone NOT NULL,
  PRIMARY KEY ("token")
);


CREATE TABLE IF NOT EXISTS "#__bfstop_allowlist" (
  "id" serial NOT NULL,
  "ipaddress" varchar(49) NOT NULL,
  "notes" varchar(255) NOT NULL DEFAULT '',
  PRIMARY KEY ("id")
);


CREATE TABLE IF NOT EXISTS "#__bfstop_knownip" (
  "id" serial NOT NULL,
  "ipaddress" varchar(45) NOT NULL,
  "username" varchar(150) NOT NULL,
  "first_success" timestamp without time zone NOT NULL,
  "last_success" timestamp without time zone NOT NULL,
  PRIMARY KEY ("id"),
  CONSTRAINT "#__bfstop_knownip_ip_username" UNIQUE ("ipaddress", "username")
);


CREATE TABLE IF NOT EXISTS "#__bfstop_dnscache" (
  "ipaddress" varchar(45) NOT NULL,
  "hostname" varchar(255) DEFAULT NULL,
  "checked_at" timestamp without time zone NOT NULL,
  PRIMARY KEY ("ipaddress")
);
