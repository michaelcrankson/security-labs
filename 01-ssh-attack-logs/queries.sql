-- SQL Security Log Analysis Lab: detections
-- Run inside: sqlite3 ssh_logs.db

-- 1. Top source IPs by failed password attempts
-- Finding: 183.62.140.253 made 286 of the 519 failed password attempts (over half).
-- Lesson: LIMIT on raw rows shows the FIRST rows, not the TOP ones; aggregate first.
SELECT src_ip, COUNT(*) AS failures
FROM ssh_logs
WHERE event_type = 'failed_password'
GROUP BY src_ip
ORDER BY failures DESC
LIMIT 10;


-- 2. Usernames attackers tried
-- Finding: root = 370 of 519 failures (~71%); 276 of those came from 183.62.140.253.
-- 62 distinct usernames tried overall: a dictionary attack (admin, support, oracle, test, guest...).
-- Lessons: text values need exact spelling + single quotes; use SELECT DISTINCT to check real values.
SELECT username, COUNT(*) AS failures
FROM ssh_logs
WHERE event_type = 'failed_password'
GROUP BY username
ORDER BY failures DESC
LIMIT 10;


-- 3. Brute force: many failures from one IP in a short window
-- Finding: 183.62.140.253 sent up to 30 failed passwords per minute; all 286 of its
-- failures landed in ~10 minutes (10:54:29 to 11:04:43), about one guess every 2 seconds.
-- Totals show HOW MUCH; grouping per minute shows HOW FAST. That speed = automated tool, not a human.
SELECT src_ip, strftime('%H:%M', ts) AS minute, COUNT(*) AS failures
FROM ssh_logs
WHERE event_type = 'failed_password'
GROUP BY src_ip, minute
ORDER BY failures DESC
LIMIT 10;


-- 4. Possible compromise: successful login from an IP that also failed
-- Finding: the only successful login was user fztu from 119.137.62.142 at 09:32:20.
-- That IP had ZERO failures: correct password first try, a ~13-minute session, then a
-- normal "disconnected by user". Looks legitimate, not a cracked account. None of the
-- attacking IPs (e.g. 183.62.140.253 on root) ever got in.
-- Caveat: a stolen (not guessed) password would look identical; confirm with the user
-- or a list of known IPs before closing it.

-- Step 1: find the successful login
SELECT ts, username, src_ip
FROM ssh_logs
WHERE event_type = 'accepted';

-- Step 2: what else did that IP do?
SELECT event_type, COUNT(*)
FROM ssh_logs
WHERE src_ip = '119.137.62.142'
GROUP BY event_type;


-- 5. Attack timeline
-- Finding: failures climbed through the morning (07: 44, 09: 133, 10: 171). The 11:00 hour
-- has 146 failures in under 5 minutes (log ends 11:04:45), so the attack was at its peak
-- when the log stops. Waves came from different IPs: 112.95.230.3 (07h), 187.141.143.180
-- + 103.99.0.122 (09h), then 183.62.140.253 dominating 10:54 onward.
-- Lesson: ORDER BY hour (no DESC) = time order; ORDER BY count DESC = biggest first.
SELECT strftime('%H', ts) AS hour, COUNT(*) AS failures
FROM ssh_logs
WHERE event_type = 'failed_password'
GROUP BY hour
ORDER BY hour;
