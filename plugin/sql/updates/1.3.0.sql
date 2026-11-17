-- fix BLOCK_87600HOURS:
UPDATE `#__bfstop_bannedip` SET duration=0 WHERE duration >= 5256000
