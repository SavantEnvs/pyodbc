"""Known-answer probes for mayhem/test.sh: fixed input -> asserted output, printed for bash to compare."""
import datetime
import decimal

import pyodbc

cnxn = pyodbc.connect("Driver={SQLite3};Database=:memory:", autocommit=True)
cur = cnxn.cursor()

row = cur.execute("select ?, ?, ?", 42, "héllo 世界", b"\x00\x01\xfe").fetchone()
print("params", row[0], row[1], row[2].hex(), type(row[2]).__name__)

cur.execute("create table t(a decimal(20,3), b varchar(20), c integer)")
cur.execute("insert into t values (?, ?, ?)", decimal.Decimal("12345.678"), "x" * 12, -7)
cur.execute("select a, b, c from t")
row = cur.fetchone()
print("decimal", repr(row[0]), len(row[1]), row[2], [d[0] for d in cur.description])

cur.executemany("insert into t(c) values (?)", [(i,) for i in range(5)])
print("count", cur.execute("select count(*), sum(c) from t").fetchone()[:])

print("named", cur.execute("select c as xyz from t where c = 3").fetchone().xyz)
print("version", pyodbc.version)
