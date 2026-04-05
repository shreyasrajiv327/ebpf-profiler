#!/bin/bash
# mysql_workload.sh — generates MySQL traffic only
# Hits: rnd_next, write_row, update_row, delete_row, index_next,
#       row_search_mvcc, buf_page_get_gen, fil_io, trx_commit,
#       lock_rec_insert_check_and_lock, os_file_read_func

DB="flamegraph_test"
USER="bench"
PASS="bench"

echo "[*] mysqld PID: $(pgrep mysqld | head -1)"

# ── Setup tables ────────────────────────────────────────────────────
echo "[*] Setting up tables..."
mysql -u$USER -p$PASS $DB 2>/dev/null << 'SQL'
CREATE TABLE IF NOT EXISTS big_table (
    id  INT PRIMARY KEY AUTO_INCREMENT,
    k   INT NOT NULL,
    c   CHAR(120) NOT NULL DEFAULT '',
    pad CHAR(60)  NOT NULL DEFAULT '',
    INDEX (k)
) ENGINE=InnoDB;

CREATE TABLE IF NOT EXISTS lock_table (
    id  INT PRIMARY KEY,
    val BIGINT DEFAULT 0,
    data VARCHAR(255) DEFAULT ''
) ENGINE=InnoDB;

INSERT IGNORE INTO lock_table VALUES
    (1,0,'r1'),(2,0,'r2'),(3,0,'r3'),(4,0,'r4'),(5,0,'r5');

CREATE TABLE IF NOT EXISTS txn_log (
    id        INT PRIMARY KEY AUTO_INCREMENT,
    ts        BIGINT,
    operation VARCHAR(64)
) ENGINE=InnoDB;
SQL

# ── Populate big_table if needed ────────────────────────────────────
ROW_COUNT=$(mysql -u$USER -p$PASS $DB -sNe "SELECT COUNT(*) FROM big_table;" 2>/dev/null)
echo "[*] big_table rows: $ROW_COUNT (need 100000)"
if [ "$ROW_COUNT" -lt 100000 ]; then
    echo "[*] Populating big_table (~30s)..."
    mysql -u$USER -p$PASS $DB 2>/dev/null << 'SQL'
DROP PROCEDURE IF EXISTS fill_big;
DELIMITER //
CREATE PROCEDURE fill_big()
BEGIN
    DECLARE i INT DEFAULT 0;
    WHILE i < 100000 DO
        INSERT INTO big_table (k, c, pad) VALUES
            (FLOOR(RAND()*100000), REPEAT(CHAR(97+FLOOR(RAND()*26)),120), REPEAT('x',60)),
            (FLOOR(RAND()*100000), REPEAT(CHAR(97+FLOOR(RAND()*26)),120), REPEAT('x',60)),
            (FLOOR(RAND()*100000), REPEAT(CHAR(97+FLOOR(RAND()*26)),120), REPEAT('x',60)),
            (FLOOR(RAND()*100000), REPEAT(CHAR(97+FLOOR(RAND()*26)),120), REPEAT('x',60)),
            (FLOOR(RAND()*100000), REPEAT(CHAR(97+FLOOR(RAND()*26)),120), REPEAT('x',60));
        SET i = i + 5;
    END WHILE;
END //
DELIMITER ;
CALL fill_big();
SQL
    echo "[+] Done populating"
fi

# ── Shrink buffer pool to force disk reads ───────────────────────────
echo "[*] Shrinking buffer pool to 8MB to force disk IO..."
sudo mysql -u root -e "SET GLOBAL innodb_buffer_pool_size = 8388608;" 2>/dev/null
sleep 2

echo "[*] Starting traffic..."

# 1. Full table scans → rnd_next, row_search_mvcc, buf_page_get_gen
for i in 1 2 3 4; do
    (while true; do
        mysql -u$USER -p$PASS $DB -e \
            "SELECT SQL_NO_CACHE SUM(k), COUNT(*), MAX(c) FROM big_table WHERE k > $((RANDOM % 50000));" \
            > /dev/null 2>&1
        sleep 0.01
    done) &
done

# 2. Index range scans → index_next, general_fetch
for i in 1 2; do
    (while true; do
        K=$((RANDOM % 90000))
        mysql -u$USER -p$PASS $DB -e \
            "SELECT SQL_NO_CACHE id,k,c FROM big_table USE INDEX(k) WHERE k BETWEEN $K AND $((K+500));" \
            > /dev/null 2>&1
        sleep 0.02
    done) &
done

# 3. Bulk inserts → write_row, trx_commit, fil_io
for i in 1 2 3; do
    (while true; do
        mysql -u$USER -p$PASS $DB -e \
            "INSERT INTO big_table (k,c,pad) VALUES
             ($((RANDOM%100000)),REPEAT('a',120),REPEAT('b',60)),
             ($((RANDOM%100000)),REPEAT('c',120),REPEAT('d',60)),
             ($((RANDOM%100000)),REPEAT('e',120),REPEAT('f',60)),
             ($((RANDOM%100000)),REPEAT('g',120),REPEAT('h',60)),
             ($((RANDOM%100000)),REPEAT('i',120),REPEAT('j',60));" \
            > /dev/null 2>&1
        sleep 0.01
    done) &
done

# 4. Concurrent updates on same rows → lock_rec_insert_check_and_lock
for i in 1 2 3 4 5 6; do
    (while true; do
        ROW=$((($RANDOM % 5) + 1))
        mysql -u$USER -p$PASS $DB -e \
            "UPDATE lock_table SET val=val+1, data=CONCAT('t$i_',NOW()) WHERE id=$ROW;" \
            > /dev/null 2>&1
        sleep 0.005
    done) &
done

# 5. Multi-statement transactions → trx_commit_for_mysql
for i in 1 2; do
    (while true; do
        mysql -u$USER -p$PASS $DB -e \
            "START TRANSACTION;
             INSERT INTO txn_log (ts,operation) VALUES (UNIX_TIMESTAMP(NOW(6)),'insert');
             UPDATE lock_table SET val=val+1 WHERE id=$((($RANDOM%5)+1));
             COMMIT;" \
            > /dev/null 2>&1
        sleep 0.02
    done) &
done

# 6. Delete → delete_row, fil_io
(while true; do
    mysql -u$USER -p$PASS $DB -e \
        "DELETE FROM big_table WHERE k < 200 LIMIT 50;" \
        > /dev/null 2>&1
    sleep 0.1
done) &

# 7. JOIN queries → multiple index_next chains
for i in 1 2; do
    (while true; do
        mysql -u$USER -p$PASS $DB -e \
            "SELECT SQL_NO_CACHE b.id,b.k,l.val
             FROM big_table b
             JOIN lock_table l ON (b.k % 5)+1 = l.id
             WHERE b.k > $((RANDOM % 90000))
             LIMIT 200;" \
            > /dev/null 2>&1
        sleep 0.03
    done) &
done

echo "[+] All workloads running — $(jobs -p | wc -l) background processes"
echo "[+] Press Ctrl-C to stop"

trap 'echo "[*] Stopping..."; kill $(jobs -p) 2>/dev/null; sudo mysql -u root -e "SET GLOBAL innodb_buffer_pool_size=134217728;" 2>/dev/null; echo "[+] Done"' INT
wait