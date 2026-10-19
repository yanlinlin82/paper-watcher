#!/bin/bash

APP_NAME=$(basename $(pwd))
echo "========== $(date) =========="
echo ">>> Updating for $APP_NAME"

if [ ! -d pubmed/updatefiles/ ]; then
    echo "ERROR: Directory 'pubmed/updatefiles/' does not exist!"
    exit 1
fi

# 防止同一站点的多个更新进程并发写同一个 SQLite 文件
LOCK_FILE="/tmp/${APP_NAME}-daily-update.lock"
exec 9>"${LOCK_FILE}"
if ! flock -n 9; then
	echo "ERROR: Another daily update for $APP_NAME is still running!"
	exit 1
fi

TODAY=$(date +%Y%m%d)
BAK_FILE=db.sqlite3.bak-${TODAY}
DONE_FILE=.updated-${TODAY}

if [ -e "${DONE_FILE}" ]; then
	echo ">>> It has been updated already today"
	exit 0
fi

# 用 SQLite 在线备份接口而非 cp：WAL 模式下 cp 会漏掉 -wal 中已提交的数据。
# 若今天的备份已存在（上次运行失败），保留它，不覆盖失败前的快照。
if [ ! -e "${BAK_FILE}" ]; then
	.venv/bin/python -c "import sqlite3, sys; src = sqlite3.connect('db.sqlite3', timeout=60); dst = sqlite3.connect(sys.argv[1]); src.backup(dst); dst.close(); src.close()" "${BAK_FILE}"
fi
find -name 'db.sqlite3.bak-*' -mtime +7 -exec rm -fv {} \;
find -maxdepth 1 -name '.updated-*' -mtime +7 -exec rm -fv {} \;

PUBMED_XML_GZ=$(find pubmed/updatefiles/ -type f -name '*.xml.gz' | sort | tail -n1)
if [ -z "${PUBMED_XML_GZ}" ]; then
    echo "ERROR: No PubMed XML file found in 'pubmed/updatefiles/'!"
    exit 1
fi
echo ">>> Latest PubMed XML file: $PUBMED_XML_GZ"

SOURCE=$(basename $PUBMED_XML_GZ .xml.gz)
echo ">>> Got source: $SOURCE"

mkdir -pv log/pubmed
SCAN_STATUS=0
.venv/bin/python scripts/scan-pubmed.py $PUBMED_XML_GZ >>log/pubmed/${SOURCE}.log 2>&1 || SCAN_STATUS=$?

if [ ${SCAN_STATUS} -ne 0 ]; then
	echo "ERROR: scan-pubmed.py failed with status ${SCAN_STATUS}, see log/pubmed/${SOURCE}.log"
	tail -n 20 log/pubmed/${SOURCE}.log
else
	tail -n1 log/pubmed/${SOURCE}.log
	touch "${DONE_FILE}"
fi

echo ">>> Generating Excel export file ..."
.venv/bin/python manage.py generate_excel

if [ ${SCAN_STATUS} -ne 0 ]; then
	echo ">>> Updating for $APP_NAME failed"
	exit ${SCAN_STATUS}
fi

echo ">>> Updating for $APP_NAME done"
