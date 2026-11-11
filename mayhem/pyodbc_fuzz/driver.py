"""Fuzz driver executed inside the embedded interpreter by pyodbc_fuzz.cc.

`run(data)` decodes the fuzzer bytes into pyodbc API calls against an in-memory SQLite database
reached through the stock unixODBC driver manager and the SQLite3 ODBC driver. Python-level
exceptions are the library's normal way of rejecting input and are swallowed; only native
crashes / sanitizer reports matter.
"""
import datetime
import decimal
import struct
import uuid

import pyodbc

CONN_STR = "Driver={SQLite3};Database=:memory:"

SQL_TYPES = [
    pyodbc.SQL_CHAR, pyodbc.SQL_VARCHAR, pyodbc.SQL_LONGVARCHAR, pyodbc.SQL_WCHAR,
    pyodbc.SQL_WVARCHAR, pyodbc.SQL_WLONGVARCHAR, pyodbc.SQL_BINARY, pyodbc.SQL_VARBINARY,
    pyodbc.SQL_LONGVARBINARY, pyodbc.SQL_DECIMAL, pyodbc.SQL_NUMERIC, pyodbc.SQL_INTEGER,
    pyodbc.SQL_SMALLINT, pyodbc.SQL_BIGINT, pyodbc.SQL_TINYINT, pyodbc.SQL_REAL,
    pyodbc.SQL_FLOAT, pyodbc.SQL_DOUBLE, pyodbc.SQL_BIT, pyodbc.SQL_TYPE_DATE,
    pyodbc.SQL_TYPE_TIME, pyodbc.SQL_TYPE_TIMESTAMP, pyodbc.SQL_GUID,
]

ENCODINGS = ["utf-8", "utf-16le", "utf-16be", "utf-16", "utf-32le", "latin-1", "ascii", "cp1252",
             "utf-8-sig", "gbk", "shift_jis", "bogus-codec"]

COLUMN_DDL = (
    "create table t(a decimal(38,10), b numeric(10,2), c varchar(40), d blob, e datetime,"
    " f integer, g real, h text, i date, j time, k bigint, l smallint, m bit, n char(8))"
)


class Reject(Exception):
    pass


# Fuzzed SQL runs on an in-memory database; statements that would reach the file system (ATTACH,
# VACUUM INTO, extension loading, PRAGMAs that name files) are rejected so each input's result
# depends on that input alone.
ALLOWED_FIRST = ("select", "insert", "update", "delete", "create", "drop", "with", "values",
                 "replace", "begin", "commit", "rollback", "alter", "explain", "{call", "{?=")
FORBIDDEN = ("attach", "vacuum", "pragma", "load_extension", "detach", "readfile", "writefile")


def safe_sql(sql):
    low = sql.lower()
    if not low.lstrip().startswith(ALLOWED_FIRST) or any(w in low for w in FORBIDDEN):
        raise Reject
    return sql


class Reader:
    def __init__(self, data):
        self.d = data
        self.p = 0

    def u8(self):
        if self.p >= len(self.d):
            return 0
        v = self.d[self.p]
        self.p += 1
        return v

    def u16(self):
        return self.u8() | (self.u8() << 8)

    def take(self, n):
        v = self.d[self.p:self.p + n]
        self.p += len(v)
        return bytes(v)

    def rest(self):
        v = self.d[self.p:]
        self.p = len(self.d)
        return bytes(v)

    def eof(self):
        return self.p >= len(self.d)

    def text(self, n=None):
        raw = self.rest() if n is None else self.take(n)
        return raw.decode("utf-8", "surrogatepass")

    def chunk(self):
        return self.take(self.u8())

    def string(self):
        return self.chunk().decode("utf-8", "surrogatepass")


def mkvalue(r):
    k = r.u8() % 18
    if k == 0:
        return None
    if k == 1:
        return int.from_bytes(r.take(r.u8() % 12), "little", signed=True)
    if k == 2:
        return struct.unpack("<d", r.take(8).ljust(8, b"\0"))[0]
    if k == 3:
        return r.string()
    if k == 4:
        return r.chunk()
    if k == 5:
        return bytearray(r.chunk())
    if k == 6:
        return decimal.Decimal(r.string())
    if k == 7:
        return bool(r.u8() & 1)
    if k == 8:
        return datetime.datetime(1 + r.u16() % 9999, 1 + r.u8() % 12, 1 + r.u8() % 28,
                                 r.u8() % 24, r.u8() % 60, r.u8() % 60, r.u16() * 15)
    if k == 9:
        return datetime.date(1 + r.u16() % 9999, 1 + r.u8() % 12, 1 + r.u8() % 28)
    if k == 10:
        return datetime.time(r.u8() % 24, r.u8() % 60, r.u8() % 60, r.u16() * 15)
    if k == 11:
        return memoryview(r.chunk())
    if k == 12:
        return uuid.UUID(bytes=r.take(16).ljust(16, b"\0"))
    if k == 13:
        return r.string() * (1 + r.u16() % 600)
    if k == 14:
        return r.chunk() * (1 + r.u16() % 600)
    if k == 15:
        return decimal.Decimal(r.u8() - 128).scaleb(r.u8() - 128)
    if k == 16:
        return int.from_bytes(r.take(r.u8() % 40), "big")
    return float(r.u8()) / (1 + r.u8())


def mkvalues(r, limit):
    return [mkvalue(r) for _ in range(r.u8() % limit)]


def consume(cur, r):
    # Exercise result-set reading through every public fetch path.
    how = r.u8() % 6
    if how == 0:
        rows = cur.fetchall()
    elif how == 1:
        rows = cur.fetchmany(1 + r.u8() % 8)
    elif how == 2:
        rows = [cur.fetchone()]
    elif how == 3:
        rows = list(cur)
    elif how == 4:
        rows = [cur.fetchval()]
    else:
        cur.skip(r.u8() % 4)
        rows = cur.fetchall()
    for row in rows:
        if row is None:
            continue
        try:
            repr(row)
            str(row)
            list(row)
            row.cursor_description
            len(row)
            if len(row):
                row[0]
                row[-1]
                row[0:1]
        except TypeError:
            repr(row)
    cur.description
    cur.rowcount
    cur.messages
    cur.nextset()


def mode_param(conn, r):
    cur = conn.cursor()
    n = 1 + r.u8() % 4
    vals = [mkvalue(r) for _ in range(n)]
    if r.u8() & 1:
        cur.setinputsizes([(SQL_TYPES[r.u8() % len(SQL_TYPES)], r.u16() % 5000, r.u8() % 40)
                           for _ in range(n)])
    cur.execute("select " + ", ".join("?" for _ in vals), *vals)
    consume(cur, r)


def mode_columns(conn, r):
    cur = conn.cursor()
    cur.execute(COLUMN_DDL)
    for _ in range(1 + r.u8() % 4):
        col = "abcdefghijklmn"[r.u8() % 14]
        cur.execute("insert into t(%s) values (?)" % col, mkvalue(r))
    if r.u8() & 1:
        cur.execute("insert into t(a, b, c, h, n) values (?, ?, ?, ?, ?)",
                    r.string(), r.string(), r.string(), r.string(), r.string())
    cur.execute("select * from t")
    consume(cur, r)
    cur.execute("select a, b from t")
    consume(cur, r)
    cur.execute("select * from t where rowid = ?", r.u8() % 6)
    consume(cur, r)


def mode_sql(conn, r):
    cur = conn.cursor()
    if r.u8() & 1:
        cur.execute(COLUMN_DDL)
    sql = safe_sql(r.text(r.u16() % 400))
    args = mkvalues(r, 6)
    cur.execute(sql, *args)
    consume(cur, r)
    cur.execute(safe_sql(r.text()), *args)
    consume(cur, r)


def mode_catalog(conn, r):
    cur = conn.cursor()
    cur.execute(COLUMN_DDL)
    which = r.u8() % 8
    a, b = r.string(), r.string()
    opt = (a or None, b or None)
    if which == 0:
        cur.tables(table=opt[0], tableType=opt[1])
    elif which == 1:
        cur.columns(table=opt[0], column=opt[1])
    elif which == 2:
        cur.primaryKeys(opt[0])
    elif which == 3:
        cur.statistics(opt[0], unique=bool(r.u8() & 1), quick=bool(r.u8() & 1))
    elif which == 4:
        cur.procedures(procedure=opt[0])
    elif which == 5:
        cur.getTypeInfo(SQL_TYPES[r.u8() % len(SQL_TYPES)])
    elif which == 6:
        cur.foreignKeys(table=opt[0], foreignTable=opt[1])
    else:
        cur.rowIdColumns(opt[0])
    consume(cur, r)
    conn.getinfo(r.u16())
    cur.execute("select * from t")
    cur.columns()
    consume(cur, r)


def mode_many(conn, r):
    cur = conn.cursor()
    cur.execute(COLUMN_DDL)
    r.u8()  # fast_executemany stays off: the SQLite3 ODBC driver segfaults in SQLExecute on parameter arrays
    ncol = 1 + r.u8() % 4
    cols = ", ".join("abcdefghijklmn"[r.u8() % 14] for _ in range(ncol))
    marks = ", ".join("?" for _ in range(ncol))
    rows = [tuple(mkvalue(r) for _ in range(ncol)) for _ in range(r.u8() % 6)]
    if r.u8() & 1:
        cur.setinputsizes([(SQL_TYPES[r.u8() % len(SQL_TYPES)], r.u16() % 800, r.u8() % 20)
                           for _ in range(ncol)])
    cur.executemany("insert into t(%s) values (%s)" % (cols, marks), rows)
    cur.execute("select * from t")
    consume(cur, r)


def mode_tvp(conn, r):
    cur = conn.cursor()
    ncols = r.u8() % 12
    rows = []
    for _ in range(r.u8() % 6):
        rows.append(tuple(mkvalue(r) for _ in range(ncols)))
    tvp = rows if r.u8() & 3 else iter(rows)
    sql = ["{call p(?)}", "select ?", "select ?, ?"][r.u8() % 3]
    extra = [mkvalue(r)]
    params = [tvp] + extra if r.u8() & 1 else extra + [tvp]
    cur.execute(sql, *params[:sql.count("?")])
    consume(cur, r)


def mode_config(conn, r):
    enc = ENCODINGS[r.u8() % len(ENCODINGS)]
    ctype = [pyodbc.SQL_CHAR, pyodbc.SQL_WCHAR][r.u8() & 1]
    conn.setencoding(encoding=enc, ctype=ctype)
    conn.setdecoding(SQL_TYPES[r.u8() % len(SQL_TYPES)], encoding=ENCODINGS[r.u8() % len(ENCODINGS)],
                     ctype=[pyodbc.SQL_CHAR, pyodbc.SQL_WCHAR][r.u8() & 1])
    conn.setdecoding(pyodbc.SQL_CHAR, encoding=enc)
    conn.setdecoding(pyodbc.SQL_WCHAR, encoding=enc)
    conn.maxwrite = r.u16() % 5000
    if r.u8() & 1:
        conn.add_output_converter(SQL_TYPES[r.u8() % len(SQL_TYPES)], lambda v: v)
    conn.autocommit = bool(r.u8() & 1)
    conn.timeout = r.u8() % 3
    pyodbc.lowercase = bool(r.u8() & 1)
    pyodbc.native_uuid = bool(r.u8() & 1)
    try:
        cur = conn.cursor()
        cur.execute("select ?, ?, ?", mkvalue(r), mkvalue(r), r.string())
        consume(cur, r)
        cur.execute(safe_sql(r.text(r.u8())))
        consume(cur, r)
    finally:
        pyodbc.lowercase = False
        pyodbc.native_uuid = False
    conn.commit()
    conn.rollback()
    conn.clear_output_converters()


MODES = [mode_param, mode_columns, mode_sql, mode_catalog, mode_many, mode_tvp, mode_config]


def run(data):
    r = Reader(data)
    mode = MODES[r.u8() % len(MODES)]
    try:
        conn = pyodbc.connect(CONN_STR, autocommit=True)
    except pyodbc.Error:
        raise SystemError("SQLite3 ODBC driver is not available")
    try:
        mode(conn, r)
    except Reject:
        return False
    except Exception:
        pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
    return True
