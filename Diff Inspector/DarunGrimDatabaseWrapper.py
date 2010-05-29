from sqlalchemy import create_engine,Table,Column,Integer,String,ForeignKey,MetaData
from sqlalchemy.orm import mapper
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base

Base=declarative_base()

class OneLocationInfo(Base):
	__tablename__='OneLocationInfo'

	id = Column(Integer, primary_key=True)
	file_id = Column( String, name = "FileID" )
	start_address = Column( Integer, name = "StartAddress" )
	end_address = Column( Integer, name = "EndAddress" )
	flag = Column( Integer, name = "Flag" )
	function_address = Column( Integer, name = "FunctionAddress" )
	block_type = Column( Integer, name = "BlockType" )
	name = Column( Integer, name = "Name" )
	disasm_lines = Column( Integer, name = "DisasmLines" )
	fingerprint = Column( Integer, name = "Fingerprint" )

	def __init__( self ):
		pass

	def __repr__(self):
		return "<OneLocationInfo('%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s', '%s' )>" % ( self.file_id, 
								self.start_address, 
								self.end_address, 
								self.flag, 
								self.function_address, 
								self.block_type, 
								self.name, 
								self.disasm_lines, 
								self.fingerprint )

class MapInfo(Base):
	__tablename__='MapInfo'

	id = Column(Integer, primary_key=True)
	file_id = Column( Integer, name = "FileID" )
	
	type = Column( Integer, name = "Type" )
	src_block = Column( Integer, name = "SrcBlock" )
	src_block_end = Column( Integer, name = "SrcBlockEnd" )
	dst = Column( Integer, name = "Dst" )

	def __init__( self ):
		pass

	def __repr__(self):
		return "<MapInfo('%d', '%d', '%d', '%d', '%d', '%d' )>" % ( self.file_id, 
								self.type, 
								self.src_block, 
								self.src_block_end, 
								self.dst )

class FileInfo(Base):
	__tablename__='FileInfo'

	id = Column(Integer, primary_key=True)
	original_file_path = Column( String, name = "OriginalFilePath" )
	computer_name = Column( String, name = "ComputerName" )
	user_name = Column( String, name = "UserName" )
	company_name = Column( String, name = "CompanyName" )
	file_version = Column( String, name = "FileVersion" )
	file_description = Column( String, name = "FileDescription" )
	internal_name = Column( String, name = "InternalName" )
	product_name = Column( String, name = "ProductName" )
	modified_time = Column( String, name = "ModifiedTime" )
	md5sum = Column( String, name = "MD5Sum" )

	def __init__( self ):
		pass

	def __repr__(self):
		return "<FileInfo('%s' )>" % ( self.original_file_path )


class MatchMap(Base):
	__tablename__='MatchMap'

	id = Column(Integer, name = "id", primary_key=True)
	source_file_id = Column(Integer, name = "TheSourceFileID" )
	target_file_id = Column(Integer, name = "TheTargetFileID" )
	source_address = Column(Integer, name = "TheSourceAddress" )
	target_address = Column(Integer, name = "TheTargetAddress" )
	match_type = Column(Integer, name = "MatchType" )
	type = Column(Integer, name = "Type" )
	sub_type = Column(Integer, name = "SubType" )
	status = Column(Integer, name = "Status" )
	match_rate = Column(Integer, name = "MatchRate" )
	source_parent_address = Column(Integer, name = "UnpatchedParentAddress" )
	target_parent_address = Column(Integer, name = "PatchedParentAddress" )

	def __init__( self ):
		pass

	def __repr__(self):
		return "<MatchMap('%d' )>" % ( self.id )

class FunctionMatchInfo(Base):
	__tablename__='FunctionMatchInfo'

	id = Column(Integer, name = "id", primary_key=True)
	source_file_id = Column(Integer, name = "TheSourceFileID" )
	target_file_id = Column(Integer, name = "TheTargetFileID" )
	source_address = Column(Integer, name = "TheSourceAddress" )
	end_address = Column(Integer, name = "EndAddress" )
	target_address = Column(Integer, name = "TheTargetAddress" )
	block_type = Column(Integer, name = "BlockType" )
	match_rate = Column(Integer, name = "MatchRate" )
	source_function_name = Column(String, name = "TheSourceFunctionName" )
	type = Column(Integer, name = "Type" )
	target_function_name = Column(String, name = "TheTargetFunctionName" )

	match_count_for_the_source = Column(Integer, name = "MatchCountForTheSource" )
	non_match_count_for_the_source = Column(Integer, name = "NoneMatchCountForTheSource" )
	match_count_with_modificationfor_the_source = Column(Integer, name = "MatchCountWithModificationForTheSource" )
	match_count_for_the_target = Column(Integer, name = "MatchCountForTheTarget" )
	non_match_count_for_the_target = Column(Integer, name = "NoneMatchCountForTheTarget" )
	match_count_with_modification_for_the_target = Column(Integer, name = "MatchCountWithModificationForTheTarget" )

	def __init__( self ):
		pass

	def __repr__(self):
		return "<FunctionMatchInfo('%d' )>" % ( self.id )

class Database:
	DebugLevel = 2
	def __init__( self, filename ):
		echo = False
		if self.DebugLevel > 2:
			echo = True
		self.Engine = create_engine( 'sqlite:///' + filename, echo = echo )

		metadata = Base.metadata
		metadata.create_all( self.Engine )

		self.Session = sessionmaker()
		self.Session.configure( bind = self.Engine )	
		self.SessionInstance = self.Session()

	def GetOneLocationInfo( self ):
		return self.SessionInstance.query( OneLocationInfo ).all()
		
	def GetFunctionMatchInfo( self ):
		return self.SessionInstance.query( FunctionMatchInfo ).all()		


if __name__ == '__main__':
	import sys
	filename = sys.argv[1]

	database = Database( filename )
	for function_match_info in database.GetFunctionMatchInfo():
		if function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
			#print function_match_info.id, function_match_info.source_file_id, function_match_info.target_file_id, 
			#function_match_info.end_address, 
			print function_match_info.source_function_name + hex(function_match_info.source_address) + '\t',
			print function_match_info.target_function_name + hex(function_match_info.target_address) + '\t',
			print str(function_match_info.block_type) + '\t',
			print str(function_match_info.type) + '\t',
			print str( function_match_info.match_rate ) + "%" + '\t',
			print function_match_info.match_count_for_the_source, function_match_info.non_match_count_for_the_source, function_match_info.match_count_with_modificationfor_the_source, function_match_info.match_count_for_the_target, function_match_info.non_match_count_for_the_target, function_match_info.match_count_with_modification_for_the_target

