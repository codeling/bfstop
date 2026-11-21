-- install script for bfstop plugin

CREATE TABLE IF NOT EXISTS #__bfstop_failedlogin (
	id int(10) NOT NULL auto_increment,
	username varchar(150) NOT NULL,
	ipaddress varchar(45) NOT NULL,
	logtime datetime NOT NULL,
	origin int NOT NULL,
	handled BOOLEAN NOT NULL DEFAULT 0,
	PRIMARY KEY  (id),
	KEY username_logtime (username, logtime),
-- the failed logins of an address within a time span: counted for every
-- failed login, listed when it gets blocked
	KEY ipaddress_logtime (ipaddress, logtime),
-- those of the last hour (adaptive delay), the purge of old ones
	KEY logtime (logtime)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


CREATE TABLE IF NOT EXISTS #__bfstop_bannedip (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	crdate datetime NOT NULL,
	duration int NOT NULL,
-- number of requests rejected because of this block, and the time of the
-- latest one (issue #219); NULL = no attempt since the block started
	attempts int unsigned NOT NULL DEFAULT 0,
	last_attempt datetime NULL DEFAULT NULL,
-- submissions of the password recovery forms while the block is active
-- (issue #285): how many since recovery_since, the start of the hour they
-- are counted in; NULL = none yet
	recovery_requests int unsigned NOT NULL DEFAULT 0,
	recovery_since datetime NULL DEFAULT NULL,
	PRIMARY KEY (id),
-- looked up for every request: addresses and networks are stored in
-- canonical form (IpHelper::canonicalEntry())
	KEY ipaddress (ipaddress)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


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
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- what the purge of old blocks keeps of them (issue #283, C14): the number of
-- blocks an address has had which were not lifted by an administrator, and
-- when the latest one began. Together with the blocks which are still there
-- this is what the duration of the next block is based on (maxBlocksBefore,
-- progressiveBlockDuration), so an attacker who returns every few weeks
-- still escalates; BlockRepository::pruneOffences() forgets the old ones.
CREATE TABLE IF NOT EXISTS #__bfstop_offence (
	ipaddress varchar(49) NOT NULL,
	blocks int unsigned NOT NULL DEFAULT 0,
	last_block datetime NOT NULL,
	PRIMARY KEY (ipaddress),
	KEY last_block (last_block)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- stores randomized tokens for unblocking an IP via an email
-- to the blocked user
-- username: the user the unblock link was sent to, to limit the links per user
-- username_lc: the same in lower case, for the lookups which must not tell
-- "Bob" from "bob" - computed by the database, see KnownIpRepository
CREATE TABLE IF NOT EXISTS #__bfstop_unblock_token (
	token varchar(40) NOT NULL,
	block_id int(10) NOT NULL,
	crdate datetime NOT NULL,
	username varchar(150) NULL DEFAULT NULL,
	username_lc varchar(150) GENERATED ALWAYS AS (LOWER(username)) STORED,
	PRIMARY KEY (token),
	KEY username_lc (username_lc)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- stores a whitelist of IPs which will never be blocked
CREATE TABLE IF NOT EXISTS #__bfstop_allowlist (
	id int(10) NOT NULL auto_increment,
	ipaddress varchar(45) NOT NULL,
	notes varchar(255) NOT NULL DEFAULT '',
	PRIMARY KEY (id),
	KEY ipaddress (ipaddress)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- records (ipaddress, username) pairs that have had at least one successful
-- login, as a risk signal (issue #76): a failed login for a username from an
-- IP that has previously logged that same user in successfully is treated as
-- less risky. Deliberately scoped to the (ipaddress, username) pair, not the
-- IP alone, so that logging in as one (e.g. self-registered) user cannot
-- lower the risk score for attempts against a different username from the
-- same IP.
CREATE TABLE IF NOT EXISTS #__bfstop_knownip (
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


-- caches reverse-DNS (PTR) lookup results per IP address (issue #103), so
-- the risk-scoring reverse-DNS signal only ever performs the actual (slow)
-- DNS lookup at most once per IP per DnsCacheRepository::TtlDays
-- window, rather than once per failed login attempt.
CREATE TABLE IF NOT EXISTS #__bfstop_dnscache (
	ipaddress varchar(45) NOT NULL,
	hostname varchar(255) DEFAULT NULL,
	checked_at datetime NOT NULL,
	PRIMARY KEY (ipaddress)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- per-username failed login statistics (issue #136): how often each
-- username was used in a failed login, and when first/last. Deliberately
-- not pruned by the automatic purge of old failed login entries, so the
-- "highscore" of attacked usernames covers the whole history; entries are
-- only removed when an admin deletes usernames not seen for a given time.
CREATE TABLE IF NOT EXISTS #__bfstop_username_stats (
	username varchar(150) NOT NULL,
	attempts int unsigned NOT NULL DEFAULT 0,
	first_attempt datetime NOT NULL,
	last_attempt datetime NOT NULL,
	PRIMARY KEY (username),
	KEY attempts (attempts),
	KEY last_attempt (last_attempt)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;


-- the plugin's own bookkeeping (name => value), apart from its settings: when
-- the maintenance last ran. In the plugin's row of #__extensions, it was
-- written by requests with the whole settings, and so raced with an
-- administrator saving them.
CREATE TABLE IF NOT EXISTS #__bfstop_state (
	name varchar(64) NOT NULL,
	value varchar(255) NOT NULL,
	changed datetime NOT NULL,
	PRIMARY KEY (name)
) DEFAULT CHARSET=utf8mb4 DEFAULT COLLATE=utf8mb4_unicode_ci;
