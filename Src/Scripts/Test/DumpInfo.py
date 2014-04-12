import sqlite3
from math import sqrt
import sys

DBFilename=sys.argv[1]
conn=sqlite3.connect(DBFilename)
conn.text_factory = str

Cursor=conn.cursor()
Cursor.execute("SELECT id,OriginalFilePath FROM FileInfo")
for row in Cursor:
	FileID=row[0]
	OriginalFilePath=row[1]
	print FileID,OriginalFilePath

FileID=int(sys.argv[2])
StartAddress=int(sys.argv[3],16)
Query="SELECT FunctionAddress,StartAddress,Name,DisasmLines FROM OneLocationInfo WHERE FileID="+str(FileID)+" AND StartAddress='"+str(StartAddress)+"'"
#print Query
print "==================================================="
print FileID,hex(StartAddress)
Cursor=conn.cursor()
Cursor.execute(Query)
for row2 in Cursor:
	FunctionAddress=int(row2[0])
	StartAddress=int(row2[1])
	Name=row2[2]
	DisasmLines=row2[3]
	print Name,FunctionAddress,StartAddress,DisasmLines
print "==================================================="
