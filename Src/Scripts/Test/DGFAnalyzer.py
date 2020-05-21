import sqlite3
from math import sqrt
import sys

class DGFAnalyzer:
	def __init__(self,Filename):
		self.Filename=Filename
		self.FunctionNames={}
		self.Address2Function={}
		conn=sqlite3.connect(self.Filename)
		conn.text_factory = str
		self.Cursor=conn.cursor()

	def CacheFunctionInfo(self):
		TmpCursor=conn.cursor()
		TmpCursor.execute("SELECT * FROM FileInfo")
		for row in TmpCursor:
			FileID=int(row[0])
			self.FunctionNames[FileID]={}
			self.Address2Function[FileID]={}
		
			self.Cursor.execute("SELECT FunctionAddress,StartAddress,Name FROM OneLocationInfo WHERE FileID="+str(FileID))
			for row in self.Cursor:
				function_address=int(row[0])
				block_address=int(row[1])
				name=row[2]
				if function_address!=0:
					self.Address2Function[FileID][block_address]=function_address
				if function_address==block_address:
					self.FunctionNames[FileID][function_address]=name

	def GetNames(self,FileID):
		if FileID==1:
			FileIDColumnName="TheSourceFileID"
			AddressColumnName="SourceAddress"
		else:
			FileIDColumnName="TheTargetFileID"
			AddressColumnName="TargetAddress"
		return (FileIDColumnName,AddressColumnName)
	
	def GetIdentifiedBlocksCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		for row in self.Cursor:
			return row[0]
	
	def GetIdentifiedFunctionsCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND BlockType=1 AND FileID="+str(FileID)+" AND StartAddress IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		for row in self.Cursor:
			return row[0]
	
	def GetMapInfoCount(self,FileID):
		self.Cursor.execute("SELECT COUNT(*) FROM MapInfo WHERE FileID="+str(FileID))
		for row in self.Cursor:
			return row[0]
		
	def GetMatchMapCount(self):
		self.Cursor.execute("SELECT COUNT(*) FROM MatchMap");
		for row in self.Cursor:
			return row[0]
	
	def GetUnidentifiedFunctionsCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND BlockType=1 AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		for row in self.Cursor:
			return row[0]
		
	def GetFullMatchedBlocksCount(self):
		self.Cursor.execute("SELECT COUNT(*) FROM MatchMap WHERE MatchRate='100'");
		for row in self.Cursor:
			return row[0]
	
	def GetUnidentifiedFunctions(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT Name FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND BlockType=1 AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		return self.Cursor
	
	def GetUnidentifiedBlocksCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		for row in self.Cursor:
			return row[0]
	
	def GetOneLocationInfoCount(self,FileID):
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID))
		for row in self.Cursor:
			return row[0]
	
	def GetCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		query="SELECT FunctionAddress,StartAddress FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap) ORDER BY FunctionAddress"
		print query
		self.Cursor.execute(query);
		for row in self.Cursor:
			function_address=int(row[0])
			block_address=int(row[1])
			function_name="("+hex(function_address)+")"
			if self.FunctionNames[FileID].has_key(function_address):
				function_name=self.FunctionNames[FileID][function_address]
			print function_name+"."+hex(block_address)

	def GetTypeStr(self,Type):
		Types=("Name","Fingerprint","Two Level fingerprint","Tree","Fingerprint Inside Function","Function")
		if len(Types)<=Type:
			return "Unknown"
		return Types[Type]

"""
c.execute("SELECT COUNT(DISTINCT(SourceAddress)) FROM MatchMap WHERE MatchRate!=100")
for row in c:
	print 'Modified Blocks',row,sqrt(row[0])

Matches={}
IdentifiedFunctions={}
c.execute("SELECT TheSourceFileID,TheTargetFileID,SourceAddress,TargetAddress,Type,MatchRate,UnpatchedParentAddress,PatchedParentAddress FROM MatchMap")
for row in c:
	TheSourceFileID=int(row[0])
	TheTargetFileID=int(row[1])

	SourceAddress=int(row[2])
	TargetAddress=int(row[3])

	TheSourceFunctionAddress=0
	if self.Address2Function[TheSourceFileID].has_key(SourceAddress):
		TheSourceFunctionAddress=self.Address2Function[TheSourceFileID][SourceAddress]

	TheTargetFunctionAddress=0
	if self.Address2Function[TheTargetFileID].has_key(TargetAddress):
		TheTargetFunctionAddress=self.Address2Function[TheTargetFileID][TargetAddress]

	if not IdentifiedFunctions.has_key(TheSourceFileID):
		IdentifiedFunctions[TheSourceFileID]={}
	if not IdentifiedFunctions[TheSourceFileID].has_key(TheSourceFunctionAddress):
		IdentifiedFunctions[TheSourceFileID][TheSourceFunctionAddress]=[]

	if not IdentifiedFunctions.has_key(TheTargetFileID):
		IdentifiedFunctions[TheTargetFileID]={}
	if not IdentifiedFunctions[TheTargetFileID].has_key(TheTargetFunctionAddress):
		IdentifiedFunctions[TheTargetFileID][TheTargetFunctionAddress]=[]
	if not Matches.has_key(TheSourceFunctionAddress):
		Matches[TheSourceFunctionAddress]=[]
	Matches[TheSourceFunctionAddress].append((SourceAddress,TheTargetFunctionAddress,TargetAddress,row[4],row[5],row[6],row[7]))

TheSourceFileID=1
TheTargetFileID=2
DoPrintAll=False
for TheSourceFunctionAddress in Matches.keys():
	SourceFunctionName=''
	SourceFunctionName=hex(TheSourceFunctionAddress)
	if self.FunctionNames[TheSourceFileID].has_key(TheSourceFunctionAddress):
		SourceFunctionName=self.FunctionNames[TheSourceFileID][TheSourceFunctionAddress]
	TheLastTargetFunctionAddress=0
	for (SourceAddress,TheTargetFunctionAddress,TargetAddress,Type,MatchRate,TheParentSourceAddress,TheParentTargetAddress) in Matches[TheSourceFunctionAddress]:
		if TheLastTargetFunctionAddress!=TheTargetFunctionAddress:
			TargetFunctionName=hex(TheTargetFunctionAddress)
			if self.FunctionNames[TheTargetFileID].has_key(TheTargetFunctionAddress):
				TargetFunctionName=self.FunctionNames[TheTargetFileID][TheTargetFunctionAddress]
			print SourceFunctionName,TargetFunctionName
			TheLastTargetFunctionAddress=TheTargetFunctionAddress
		if MatchRate!=100 or DoPrintAll:
			print '\t',hex(SourceAddress),hex(TargetAddress),GetTypeStr(Type),MatchRate,hex(TheParentSourceAddress),hex(TheParentTargetAddress)

IdentifiedFunctions[TheTargetFileID][TheTargetFunctionAddress]=[]
for FileID in self.FunctionNames.keys():
	for FunctionAddress in self.FunctionNames[FileID].keys():
		if IdentifiedFunctions.has_key(FileID) and not IdentifiedFunctions[FileID].has_key(FunctionAddress):
			print 'Unidentified Function',FileID,self.FunctionNames[FileID][FunctionAddress],hex(FunctionAddress)
			

"""

