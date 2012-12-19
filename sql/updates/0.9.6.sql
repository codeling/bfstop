-- prevent information disclosure - don't store password
alter table #__bfstop_failedlogin drop column `password`;

