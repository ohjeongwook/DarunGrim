import sqlite3
from math import sqrt
import sys

class DGFAnalyzer:
	DebugLevel = 0
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
			AddressColumnName="TheSourceAddress"
		else:
			FileIDColumnName="TheTargetFileID"
			AddressColumnName="TheTargetAddress"
		return (FileIDColumnName,AddressColumnName)
	
	def RetrieveFunctionBasicBlockMap(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)

		FunctionHash={}
		self.Cursor.execute( "SELECT FunctionAddress,StartAddress FROM OneLocationInfo WHERE FileID='" + str(FileID) + "' AND FunctionAddress!=0 ORDER BY FunctionAddress" );
		for row in self.Cursor:
			FunctionAddress = row[0]
			StartAddress = row[1]
			
			if not FunctionHash.has_key(FunctionAddress):
				FunctionHash[FunctionAddress] = []
			FunctionHash[FunctionAddress].append( StartAddress )

		if self.DebugLevel > 2:
			print len(FunctionHash.keys())
			print len(FunctionHash)

		FunctionMemberCounts=[]
		for FunctionAddress in FunctionHash.keys():
			FunctionMemberCounts.append( len(FunctionHash[FunctionAddress]) )
		FunctionMemberCounts.sort()
		return FunctionMemberCounts

	def RetrievePatternAddresses(self,FileID,Pattern):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)

		FunctionHash={}
		self.Cursor.execute( "SELECT FunctionAddress,StartAddress FROM OneLocationInfo WHERE FileID='" + str(FileID) + "' AND DisasmLines like '" + Pattern + "' ORDER BY FunctionAddress" );
		
		Results=[]
		for row in self.Cursor:
			Results.append( (row[0],row[1] ) )		
		return Results

	def RetrieveDisasmLines(self,FileID,Address):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)

		FunctionHash={}
		self.Cursor.execute( "SELECT DisasmLines FROM OneLocationInfo WHERE FileID='" + str(FileID) + "' AND StartAddress='" + str(Address) + "'" );
		
		Results=[]
		for row in self.Cursor:
			return row[0]
		return ""

	def GetDisasmLinesLength(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)

		FunctionHash={}
		self.Cursor.execute( "SELECT DisasmLines FROM OneLocationInfo WHERE FileID='" + str(FileID) + "'");

		TotalLength=0
		for row in self.Cursor:
			TotalLength += len(row[0])
		return TotalLength

	def RetrieveFingerprint(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)

		FunctionHash={}
		self.Cursor.execute( "SELECT Fingerprint FROM OneLocationInfo WHERE FileID='" + str(FileID) + "'");
		
		TotalLength=0
		for row in self.Cursor:
			TotalLength += len(row[0])
		return TotalLength

	def GetMaximumFingerPrintLength(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)

		FunctionHash={}
		self.Cursor.execute( "SELECT StartAddress, Fingerprint FROM OneLocationInfo WHERE FileID='" + str(FileID) + "'");
		
		MaximumLength=0
		for row in self.Cursor:
			start_address = row[0]
			finger_print = row[1]
			if MaximumLength < len( finger_print ):
				MaximumLength = len( finger_print )
				MaximuLengthAddress = start_address
				
		return (MaximuLengthAddress, MaximumLength)

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
		try:
			self.Cursor.execute("SELECT COUNT(*) FROM MapInfo WHERE FileID="+str(FileID))
			for row in self.Cursor:
				return row[0]
		except:
			return 0
		
	def GetMatchMapCount(self):
		try:
			self.Cursor.execute("SELECT COUNT(*) FROM MatchMap");
			for row in self.Cursor:
				return row[0]
		except:
			return 0

	def GetMatchedFunctionList(self, Options={"matched":1} , Offset = None, Limit = None, RetrieveCount = False ):
		if RetrieveCount:
			Columns = "COUNT(*)"
		else:
			Columns = "TheSourceFileID, TheTargetFileID, TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget"
		
		Query = "SELECT " + Columns + " FROM FunctionMatchInfo"	

		IncludeUnidentifiedBlock = True
		Conditions = []

		include_matched = False
		if ( Options.has_key( "matched" ) and Options[ "matched" ] == 1 ):
			include_matched = True
		include_modified = False
		if ( Options.has_key( "modified" ) and Options[ "modified" ] == 1 ):
			include_modified = True	
			
		if include_matched and include_modified:
			pass
		elif include_matched:
			Conditions.append( 'MatchRate == 100 ' )
		elif include_modified:
			Conditions.append( 'MatchRate != 100 ' )

		if not ( Options.has_key( "unidentified" ) and Options[ "unidentified" ] == 1 ):
			Conditions.append( 'TheSourceAddress != 0 ' )
			Conditions.append( 'TheTargetAddress != 0 ' )

		ConditionStr = ''
		for Condition in Conditions:
			if ConditionStr == '':
				ConditionStr += Condition
			else:
				ConditionStr += ' AND ' + Condition

		if ConditionStr != '':
			Query += ' WHERE ' + ConditionStr

		if Limit:
			Query += ' LIMIT ' + str( Limit )

		if Offset:
			Query += ' OFFSET ' + str( Offset )
		
		if self.DebugLevel > 2:
			print Query

		Results=[]
		try:
			self.Cursor.execute( Query );
			
			if RetrieveCount:
				for ( Count ) in self.Cursor:
					return Count
			else:
				for ( TheSourceFileID, TheTargetFileID, TheSourceAddress, EndAddress, TheTargetAddress, BlockType, MatchRate, TheSourceFunctionName, Type, TheTargetFunctionName, MatchCountForTheSource, NoneMatchCountForTheSource, MatchCountWithModificationForTheSource, MatchCountForTheTarget, NoneMatchCountForTheTarget, MatchCountWithModificationForTheTarget ) in self.Cursor:
					result = {}
					result["TheSourceFunctionName"] = TheSourceFunctionName
					result["TheSourceAddress"] = TheSourceAddress
					result["TheTargetFunctionName"] = TheTargetFunctionName
					result["TheTargetAddress"] = TheTargetAddress
					result["MatchRate"] = MatchRate
					result["MatchCountForTheSource"] = MatchCountForTheSource
					result["MatchCountWithModificationForTheSource"] = MatchCountWithModificationForTheSource
					result["NoneMatchCountForTheSource"] = NoneMatchCountForTheSource
					result["MatchCountForTheTarget"] = MatchCountForTheTarget
					result["MatchCountWithModificationForTheTarget"] = MatchCountWithModificationForTheTarget
					result["NoneMatchCountForTheTarget"] = NoneMatchCountForTheTarget
					Results.append( result )
		except:
			pass
		return Results
	
	def GetFunctionMemberMatchList(self,Options=("matched")):
		#modified,unidentified
		pass

	def GetFunctionDisasmLinesHash( self, FileID, FunctionAddress ):
		#BOOL OneIDAClientManager::RetrieveOneLocationInfo( DWORD FunctionAddress )
		self.Cursor.execute( "SELECT StartAddress, DisasmLines, Name FROM OneLocationInfo WHERE FileID = '%u' AND FunctionAddress = '%d'" % ( FileID, FunctionAddress ) )
		DisasmLinesHash={}
		for row in self.Cursor:
			DisasmLinesHash[row[0]] = row[1]
		return DisasmLinesHash

	def DumpDisasmLineHash( self, DisasmLineHash ):
		addresses = DisasmLineHash.keys()
		addresses.sort()
		
		for address in addresses:
			print hex(address)
			print DisasmLineHash[address]
			print ""

	def GetMatchMapForFunction( self, FileID, FunctionAddress ):
		self.Cursor.execute( "SELECT TheSourceAddress, TheTargetAddress FROM MatchMap WHERE TheSourceAddress IN (SELECT StartAddress Name FROM OneLocationInfo WHERE FileID = '%u' AND FunctionAddress = '%d')" % ( FileID, FunctionAddress ) )
		MatchHash = {}
		for row in self.Cursor:
			MatchHash[row[0]] = row[1]
		return MatchHash

	def GetMatchedFunctionMemberList( self, FunctionAddresses ):
		DisasmLineHash=[]
		DisasmLineHash.append( self.GetFunctionDisasmLines( "Source", FunctionAddresses[0] ) )
		DisasmLineHash.append( self.GetFunctionDisasmLines( "Target", FunctionAddresses[1] ) )
		
		#self.DumpDisasmLineHash( DisasmLineHash[0] )
		#self.DumpDisasmLineHash( DisasmLineHash[1] )

		MatchMap = self.GetMatchMapForFunction( 1, FunctionAddresses[0] )
		
		#for Src in MatchMap.keys():
		#	print hex(Src), hex(MatchMap[Src])
			
		return ( DisasmLineHash, MatchMap )

		#BOOL OneIDAClientManager::Retrieve(DBWrapper *InputDB, int FileID, BOOL bRetrieveDataForAnalysis, DWORD FunctionAddress )
		#self.Cursor.execute( "SELECT Type, SrcBlock, Dst From MapInfo WHERE FileID = %u AND SrcBlock IN (SELECT StartAddress FROM OneLocationInfo WHERE FileID = '%d' AND FunctionAddress='%d') AND Dst IN (SELECT StartAddress FROM OneLocationInfo WHERE FileID = '%d' AND FunctionAddress='%d') ORDER BY ID ASC" % ( FileID, FileID, FunctionAddress, FileID, FunctionAddress ) )
		#for row in self.Cursor:
		#	print row

	def GetUnidentifiedFunctionsCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND BlockType=1 AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		for row in self.Cursor:
			return row[0]
		
	def GetFullMatchedBlocksCount(self):
		try:
			self.Cursor.execute("SELECT COUNT(*) FROM MatchMap WHERE MatchRate='100'");
			for row in self.Cursor:
				return row[0]
		except:
			return 0
	
	def GetUnidentifiedFunctions(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		self.Cursor.execute("SELECT Name FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND BlockType=1 AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
		return self.Cursor
	
	def GetUnidentifiedBlocksCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		try:
			self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap)");
			for row in self.Cursor:
				return row[0]
		except:
			return 0
	
	def GetOneLocationInfoCount(self,FileID):
		self.Cursor.execute("SELECT COUNT(*) FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID))
		for row in self.Cursor:
			return row[0]
	
	def GetCount(self,FileID):
		(FileIDColumnName,AddressColumnName)=self.GetNames(FileID)
		query="SELECT FunctionAddress,StartAddress FROM OneLocationInfo WHERE FunctionAddress!=0 AND Fingerprint!='' AND FileID="+str(FileID)+" AND StartAddress NOT IN (SELECT "+AddressColumnName+" FROM MatchMap) ORDER BY FunctionAddress"
		if self.DebugLevel > 2:
			print query
		self.Cursor.execute(query);
		for row in self.Cursor:
			function_address=int(row[0])
			block_address=int(row[1])
			function_name="("+hex(function_address)+")"
			if self.FunctionNames[FileID].has_key(function_address):
				function_name=self.FunctionNames[FileID][function_address]
			if self.DebugLevel > 2:
				print function_name+"."+hex(block_address)

	def GetTypeStr(self,Type):
		Types=("Name","Fingerprint","Two Level fingerprint","Tree","Fingerprint Inside Function","Function")
		if len(Types)<=Type:
			return "Unknown"
		return Types[Type]

"""
c.execute("SELECT COUNT(DISTINCT(TheSourceAddress)) FROM MatchMap WHERE MatchRate!=100")
for row in c:
	print 'Modified Blocks',row,sqrt(row[0])

Matches={}
IdentifiedFunctions={}
c.execute("SELECT TheSourceFileID,TheTargetFileID,TheSourceAddress,TheTargetAddress,Type,MatchRate,UnpatchedParentAddress,PatchedParentAddress FROM MatchMap")
for row in c:
	TheSourceFileID=int(row[0])
	TheTargetFileID=int(row[1])

	TheSourceAddress=int(row[2])
	TheTargetAddress=int(row[3])

	TheSourceFunctionAddress=0
	if self.Address2Function[TheSourceFileID].has_key(TheSourceAddress):
		TheSourceFunctionAddress=self.Address2Function[TheSourceFileID][TheSourceAddress]

	TheTargetFunctionAddress=0
	if self.Address2Function[TheTargetFileID].has_key(TheTargetAddress):
		TheTargetFunctionAddress=self.Address2Function[TheTargetFileID][TheTargetAddress]

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
	Matches[TheSourceFunctionAddress].append((TheSourceAddress,TheTargetFunctionAddress,TheTargetAddress,row[4],row[5],row[6],row[7]))

TheSourceFileID=1
TheTargetFileID=2
DoPrintAll=False
for TheSourceFunctionAddress in Matches.keys():
	TheSourceFunctionName=''
	TheSourceFunctionName=hex(TheSourceFunctionAddress)
	if self.FunctionNames[TheSourceFileID].has_key(TheSourceFunctionAddress):
		TheSourceFunctionName=self.FunctionNames[TheSourceFileID][TheSourceFunctionAddress]
	TheLastTargetFunctionAddress=0
	for (TheSourceAddress,TheTargetFunctionAddress,TheTargetAddress,Type,MatchRate,TheParentSourceAddress,TheParentTargetAddress) in Matches[TheSourceFunctionAddress]:
		if TheLastTargetFunctionAddress!=TheTargetFunctionAddress:
			TheTargetFunctionName=hex(TheTargetFunctionAddress)
			if self.FunctionNames[TheTargetFileID].has_key(TheTargetFunctionAddress):
				TheTargetFunctionName=self.FunctionNames[TheTargetFileID][TheTargetFunctionAddress]
			print TheSourceFunctionName,TheTargetFunctionName
			TheLastTargetFunctionAddress=TheTargetFunctionAddress
		if MatchRate!=100 or DoPrintAll:
			print '\t',hex(TheSourceAddress),hex(TheTargetAddress),GetTypeStr(Type),MatchRate,hex(TheParentSourceAddress),hex(TheParentTargetAddress)

IdentifiedFunctions[TheTargetFileID][TheTargetFunctionAddress]=[]
for FileID in self.FunctionNames.keys():
	for FunctionAddress in self.FunctionNames[FileID].keys():
		if IdentifiedFunctions.has_key(FileID) and not IdentifiedFunctions[FileID].has_key(FunctionAddress):
			print 'Unidentified Function',FileID,self.FunctionNames[FileID][FunctionAddress],hex(FunctionAddress)
			

"""
