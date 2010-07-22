import sqlite3
from math import sqrt

conn=sqlite3.connect(r'T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Bin\tcpip.dgf')
conn.text_factory = str
c=conn.cursor()
c.execute("SELECT * FROM FileInfo")
for row in c:
	print row
	FileID=row[0]

	c2=conn.cursor()
	c2.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID))
	for row2 in c2:
		print '\tOneLocationInfo Count',row2,sqrt(row2[0])

	c2.execute("SELECT COUNT(*) FROM MapInfo WHERE FileID="+str(FileID))
	for row2 in c2:
		print '\tMapInfo Count',row2
	
	if FileID==1:
		FileIDColumnName="TheSourceFileID"
		AddressColumnName="TheSourceAddress"
	else:
		FileIDColumnName="TheTargetFileID"
		AddressColumnName="TheTargetAddress"

	c2.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress IN (SELECT "+AddressColumnName+" FROM MatchMap)");
	for row2 in c2:
		print '\tIdentified Blocks',row2
		
	c2.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
	for row2 in c2:
		print '\tUnidentified Blocks',row2

c.execute("SELECT COUNT(DISTINCT(TheSourceAddress)) FROM MatchMap")
for row2 in c:
	print 'Matched Blocks',row2


c.execute("SELECT COUNT(DISTINCT(TheSourceAddress)) FROM MatchMap WHERE MatchRate!=100")
for row2 in c:
	print 'Modified Blocks',row2,sqrt(row2[0])

import msvcrt
msvcrt.getch()
