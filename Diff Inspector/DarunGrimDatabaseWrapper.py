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

	def GetFunctionDisasmLinesMap( self, file_id, function_address):
		disasm_lines_hash={}

		for one_location_info in self.SessionInstance.query( OneLocationInfo ).filter_by( file_id = file_id, function_address=function_address ).all():
			disasm_lines_hash[one_location_info.start_address] = one_location_info.disasm_lines
		return disasm_lines_hash

	def GetMatchMapForFunction( self, file_id, function_address ):
		match_hash = {}
		for match_map in self.SessionInstance.query( MatchMap ).filter( MatchMap.source_address.in_(self.SessionInstance.query( OneLocationInfo.start_address ).filter_by( file_id = file_id, function_address=function_address))).all():
			match_hash[ match_map.source_address ] = ( match_map.target_address, match_map.match_rate )
		return match_hash

	def GetDisasmComparisonTable( self, source_data, target_data, match_map ):
		DebugLevel = 0
		left_addresses = source_data.keys()
		left_addresses.sort()
	
		right_addresses = target_data.keys()
		right_addresses.sort()
		
		right_addressesIndex={}	
		index = 0
		for address in right_addresses:
			right_addressesIndex[address] = index
			index += 1
		
		disasm_table={}
		Checkedright_addresses={}
		left_address_index = 0
		for left_address in left_addresses:
			right_address_index = None
			match_rate = 0
			maximum_index = left_address_index
			if match_map.has_key( left_address ):
				right_address = match_map[ left_address ][0]
				match_rate = match_map[ left_address ][1]
				Checkedright_addresses[ right_address ] = 1
				
				if right_addressesIndex.has_key( right_address ):
					right_address_index = right_addressesIndex[right_address]
					if DebugLevel > 2:
						print left_address_index, right_address_index
					
					if left_address_index > right_address_index:
						maximum_index = left_address_index
					elif left_address_index < right_address_index:
						maximum_index = right_address_index
	
			while disasm_table.has_key( maximum_index ):
				maximum_index += 1
	
			disasm_table[ maximum_index ] = ( left_address_index, right_address_index, match_rate )
			left_address_index += 1
	
		for right_address in right_addressesIndex:
			if not Checkedright_addresses.has_key( right_address ):
				right_address_index = right_addressesIndex[right_address]
				
				new_disasm_table = {}
				if disasm_table.has_key( right_address_index ):
					for index in disasm_table.keys():
						if index >= right_address_index:
							new_disasm_table[ index + 1 ] = disasm_table[ index ]
						else:
							new_disasm_table[ index ] = disasm_table[ index ]
					new_disasm_table[right_address_index] = ( None, right_address_index, 0 )
					disasm_table = new_disasm_table
				else:
					disasm_table[right_address_index] = ( None, right_address_index, 0 )
	
		if DebugLevel > 2:
			print disasm_table

		indexes = disasm_table.keys()
		indexes.sort()
	
		disasm_blocks=[]
	
		for index in indexes:
			( left_address_index, right_address_index, match_rate ) = disasm_table[index]
	
			left_address = 0
			right_address = 0
			if left_address_index:
				left_address = left_addresses[ left_address_index ]
				
			if right_address_index:
				right_address = right_addresses[ right_address_index ]
	
			if DebugLevel > 2:
				print index, ':', left_address_index, hex(left_address), right_address_index, hex(right_address)
	
			left_lines=()
			right_lines=()
	
			if source_data.has_key(left_address):
				left_lines = source_data[ left_address ].split('\n')
	
			if target_data.has_key(right_address):
				right_lines = target_data[ right_address ].split('\n')
		
			if DebugLevel > 2:
				print 'Split Lines'
				print left_lines, right_lines

			disasm_blocks.append( ( left_address, left_lines, right_address, right_lines, match_rate ) )
		return disasm_blocks

	def GetDisasmLinesSideBySide(self, left_lines, right_lines ):
		disasm_lines=[]
		i = 0
		while 1:
			left_line = ''
			if len(left_lines) > i:
				left_line = left_lines[i]
			right_line = ''
			if len(right_lines) > i:
				right_line = right_lines[i]

			if left_line=='' and right_line=='':
				break

			disasm_lines.append( (left_line, right_line) )
			i += 1
		return disasm_lines

	def GetAlignedDisasmText(self, disasm_lines ):
		disasm_text = ''
		maximum_left_line_length = 0
		for (left_line, right_line) in disasm_lines:
			if len( left_line ) > maximum_left_line_length:
				maximum_left_line_length = len( left_line )
		
		maximum_left_line_length += 10
		for (left_line, right_line) in disasm_lines:
			space_len = maximum_left_line_length - len( left_line )
			disasm_text += left_line + " " * space_len + right_line + '\n'
		return disasm_text

	def GetDisasmText(self, comparison_table ):
		disasm_lines = []
		for ( left_address, left_lines, right_address, right_lines, match_rate ) in comparison_table:
			disasm_lines += self.GetDisasmLinesSideBySide( left_lines, right_lines )

		return self.GetAlignedDisasmText( disasm_lines )

	def GetDisasmComparisonTextByFunctionAddress( self, source_function_address, target_function_address ):
		source_disasm_lines_hash = self.GetFunctionDisasmLinesMap( 1, source_function_address )
		target_disasm_lines_hash = self.GetFunctionDisasmLinesMap( 2, target_function_address )
		match_map = self.GetMatchMapForFunction( 1, source_function_address )
		return self.GetDisasmComparisonTable( source_disasm_lines_hash, target_disasm_lines_hash, match_map )

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
			#print database.GetFunctionDisasmLinesMap( function_match_info.source_file_id, function_match_info.source_address )
			#print database.GetMatchMapForFunction( function_match_info.source_file_id, function_match_info.source_address )
			disasm_table = database.GetDisasmComparisonTextByFunctionAddress( function_match_info.source_address, function_match_info.target_address )
			print database. GetDisasmText( disasm_table )

