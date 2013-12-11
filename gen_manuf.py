
# Example entry:
# 00:00:01	Xerox                  # XEROX CORPORATION

import re
r = re.compile(

    # MAC address prefix (3 octets).
    r"([0-9A-Fa-f][0-9A-Fa-f][\:\-\.]"
    r"[0-9A-Fa-f][0-9A-Fa-f][\:\-\.]"
    r"[0-9A-Fa-f][0-9A-Fa-f])"

    # Separator.
    r"[ \t]+"

    # 8-char short manufacturer name.
    r"([^ \t]+)"

    # Separator.
    r"[ \t]+\#[ \t]"

    # Full manufacturer name.
    r"(.+)"
)

import codecs
d = {}
with codecs.open("manuf.txt", "rU", "utf-8") as f:
    for line in f:
        line = line.encode("utf-8")
        for m in r.finditer(line):
            prefix, code, name = m.groups()
            d[prefix] = (code, name)

from pprint import pformat
with open("manuf.py", "w") as f:
    f.write("#!/usr/bin/env python\n")
    f.write("# -*- coding: utf-8 -*-\n\n")
    f.write("MAC_PREFIX_TO_MANUFACTURER = ")
    f.write(pformat(d))
    f.write("\n")

import cPickle
with open("manuf.pickle", "wb") as f:
    cPickle.dump(d, f, -1)

import marshal
with open("manuf.marshal", "wb") as f:
    marshal.dump(d, f)

import anydbm
db = anydbm.open("manuf.dbm", 'c')
for k,v in d.iteritems():
    db[k] = ",".join(v)
db.close()

import sqlite3
import os, os.path
if os.path.exists("manuf.db"):
    os.unlink("manuf.db")
db = sqlite3.connect("manuf.db")
try:
    c = db.cursor()
    try:
        c.execute(
            "CREATE TABLE `manufacturer` ("
            "    `prefix` CHAR(8) PRIMARY KEY NOT NULL,"
            "    `code` VARCHAR(8) NOT NULL,"
            "    `name` TEXT NOT NULL"
            ");"
        )
        for prefix in d:
            code, name = d[prefix]
            code = code.decode("utf-8")
            name = name.decode("utf-8")
            c.execute(
                "INSERT INTO `manufacturer` VALUES (?, ?, ?);",
                (prefix, code, name)
            )
    finally:
        db.commit()
        c.close()
finally:
    db.close()

del d

from time import time
from random import randint

import pickle

td = []
for i in xrange(30):
    t1 = time()
    with open("manuf.pickle", "rb") as f:
        d = pickle.load(f)
    t2 = time()
    td.append(t2 - t1)
import numpy
print "Pickle: %s seconds to load." % numpy.mean(td)
del d

import cPickle

td = []
for i in xrange(100):
    t1 = time()
    with open("manuf.pickle", "rb") as f:
        d = cPickle.load(f)
    t2 = time()
    td.append(t2 - t1)
import numpy
print "C Pickle: %s seconds to load." % numpy.mean(td)
del d

import marshal

td = []
for i in xrange(100):
    t1 = time()
    with open("manuf.marshal", "rb") as f:
        d = marshal.load(f)
    t2 = time()
    td.append(t2 - t1)
import numpy
print "Marshal: %s seconds to load." % numpy.mean(td)
td = []
for i in xrange(100000):
    a = randint(0, 16)
    b = randint(0, 16)
    c = randint(0, 16)
    x = "%.2x:%.2x:%.2x" % (a, b, c)
    t1 = time()
    try:
        d[x][1]
    except KeyError:
        pass
    t2 = time()
    td.append(t2 - t1)
print "Dict: %s to access." % numpy.mean(td)
del d

import anydbm

td = []
for i in xrange(1000):
    t1 = time()
    d = anydbm.open("manuf.dbm")
    t2 = time()
    td.append(t2 - t1)
import numpy
print "AnyDBM: %s seconds to load." % numpy.mean(td)
td = []
for i in xrange(100000):
    a = randint(0, 16)
    b = randint(0, 16)
    c = randint(0, 16)
    x = "%.2x:%.2x:%.2x" % (a, b, c)
    t1 = time()
    try:
        d[x][1]
    except KeyError:
        pass
    t2 = time()
    td.append(t2 - t1)
print "AnyDBM: %s to access." % numpy.mean(td)
del d

import sqlite3
td = []
for i in xrange(1000):
    t1 = time()
    db = sqlite3.connect("manuf.db")
    t2 = time()
    db.close()
    td.append(t2 - t1)
import numpy
print "SQLite3: %s seconds to load." % numpy.mean(td)
td = []
db = sqlite3.connect("manuf.db")
for i in xrange(100000):
    a = randint(0, 16)
    b = randint(0, 16)
    c = randint(0, 16)
    x = "%.2x:%.2x:%.2x" % (a, b, c)
    t1 = time()
    c = db.cursor()
    c.execute(
        "SELECT `code`, `name` FROM `manufacturer` WHERE `prefix` = ?;",
        (x,)
    )
    c.close()
    t2 = time()
    td.append(t2 - t1)
db.close()
print "SQLite3: %s to access." % numpy.mean(td)
td = []
for i in xrange(1000):
    a = randint(0, 16)
    b = randint(0, 16)
    c = randint(0, 16)
    x = "%.2x:%.2x:%.2x" % (a, b, c)
    t1 = time()
    db = sqlite3.connect("manuf.db")
    c = db.cursor()
    c.execute(
        "SELECT `code`, `name` FROM `manufacturer` WHERE `prefix` = ?;",
        (x,)
    )
    c.close()
    db.close()
    t2 = time()
    td.append(t2 - t1)
print "SQLite3: %s to access from scratch." % numpy.mean(td)
