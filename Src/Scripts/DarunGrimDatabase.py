from sqlalchemy import create_engine,Table,Column,Integer,String,Text,ForeignKey,MetaData,BLOB,CLOB
from sqlalchemy.orm import mapper, sessionmaker, aliased
from sqlalchemy.sql import exists
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import engine
from sqlalchemy.engine.reflection import Inspector
import os
import pprint

Base=declarative_base()

class FileList(Base):
	__tablename__='FileList'

	id=Column(Integer,primary_key=True)
	type=Column(String, name='Type')
	filename=Column(String,name='Filename')
	file_id=Column(Integer,name='FileID')

	def __init__(self):
		pass

	def __repr__(self):
		return "<FileList('%d', '%s', '%s', '%d')>" % (self.id,self.type,self.filename,self.file_id)

class OneLocationInfo(Base):
	__tablename__='OneLocationInfo'

	id = Column(Integer, primary_key=True)
	file_id = Column(String, name = "FileID")
	start_address = Column(Integer, name = "StartAddress")
	end_address = Column(Integer, name = "EndAddress")
	flag = Column(Integer, name = "Flag")
	function_address = Column(Integer, name = "FunctionAddress")
	block_type = Column(Integer, name = "BlockType")
	name = Column(String, name = "Name")
	disasm_lines = Column(String, name = "DisasmLines")
	fingerprint = Column(String, name = "Fingerprint")

	def __init__(self):
		pass

	def __repr__(self):
		return "<OneLocationInfo('%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s', '%s')>" % (self.file_id, 
								self.start_address, 
								self.end_address, 
								self.flag, 
								self.function_address, 
								self.block_type, 
								self.name, 
								self.disasm_lines, 
								self.fingerprint)

CALL = 0
CREF_FROM = 1
CREF_TO = 2
DREF_FROM = 3
DREF_TO = 4
CALLED = 5

class MapInfo(Base):
	__tablename__='MapInfo'

	id = Column(Integer, primary_key=True)
	file_id = Column(Integer, name = "FileID")
	
	type = Column(Integer, name = "Type")
	src_block = Column(Integer, name = "SrcBlock")
	src_block_end = Column(Integer, name = "SrcBlockEnd")
	dst = Column(Integer, name = "Dst")

	def __init__(self):
		pass

	def __repr__(self):
		return "<MapInfo('%d', '%d', '%d', '%d', '%d', '%d')>" % (self.file_id, 
								self.type, 
								self.src_block, 
								self.src_block_end, 
								self.dst)

class FileInfo(Base):
	__tablename__='FileInfo'

	id = Column(Integer, primary_key=True)
	original_file_path = Column(String, name = "OriginalFilePath")
	computer_name = Column(String, name = "ComputerName")
	user_name = Column(String, name = "UserName")
	company_name = Column(String, name = "CompanyName")
	file_version = Column(String, name = "FileVersion")
	file_description = Column(String, name = "FileDescription")
	internal_name = Column(String, name = "InternalName")
	product_name = Column(String, name = "ProductName")
	modified_time = Column(String, name = "ModifiedTime")
	md5sum = Column(String, name = "MD5Sum")

	def __init__(self):
		pass

	def __repr__(self):
		return "<FileInfo('%s')>" % (self.original_file_path)


class MatchMap(Base):
	__tablename__='MatchMap'

	id = Column(Integer, name = "id", primary_key=True)
	source_file_id = Column(Integer, name = "TheSourceFileID")
	target_file_id = Column(Integer, name = "TheTargetFileID")
	source_address = Column(Integer, name = "TheSourceAddress")
	target_address = Column(Integer, name = "TheTargetAddress")
	match_type = Column(Integer, name = "MatchType")
	type = Column(Integer, name = "Type")
	sub_type = Column(Integer, name = "SubType")
	status = Column(Integer, name = "Status")
	match_rate = Column(Integer, name = "MatchRate")
	source_parent_address = Column(Integer, name = "UnpatchedParentAddress")
	target_parent_address = Column(Integer, name = "PatchedParentAddress")

	def __init__(self):
		pass

	def __repr__(self):
		return "<MatchMap('%d', '%d', '%d', '%X', '%X', '%d', '%d', '%d', '%d', '%d', '%X', '%X' )>" % (self.id, self.source_file_id, self.target_file_id, self.source_address, self.target_address, self.match_type, self.type, self.sub_type, self.status, self.match_rate, self.source_parent_address, self.target_parent_address)

class FunctionMatchInfo(Base):
	__tablename__='FunctionMatchInfo'

	id = Column(Integer, name = "id", primary_key=True)
	source_file_id = Column(Integer, name = "TheSourceFileID")
	target_file_id = Column(Integer, name = "TheTargetFileID")
	source_address = Column(Integer, name = "TheSourceAddress")
	end_address = Column(Integer, name = "EndAddress")
	target_address = Column(Integer, name = "TheTargetAddress")
	block_type = Column(Integer, name = "BlockType")
	match_rate = Column(Integer, name = "MatchRate")
	source_function_name = Column(String, name = "TheSourceFunctionName")
	type = Column(Integer, name = "Type")
	target_function_name = Column(String, name = "TheTargetFunctionName")

	match_count_for_the_source = Column(Integer, name = "MatchCountForTheSource")
	non_match_count_for_the_source = Column(Integer, name = "NoneMatchCountForTheSource")
	match_count_with_modificationfor_the_source = Column(Integer, name = "MatchCountWithModificationForTheSource")
	match_count_for_the_target = Column(Integer, name = "MatchCountForTheTarget")
	non_match_count_for_the_target = Column(Integer, name = "NoneMatchCountForTheTarget")
	match_count_with_modification_for_the_target = Column(Integer, name = "MatchCountWithModificationForTheTarget")
	security_implications_score = Column(Integer, name = "SecurityImplicationsScore")

	def __init__(self):
		pass

	def __repr__(self):
		return "<FunctionMatchInfo('%d')>" % (self.id)

class SourceOneLocationInfo(Base):
	__tablename__='OneLocationInfo'
	__table_args__={'schema': 'Source'}

	id = Column(Integer, primary_key=True)
	file_id = Column(String, name = "FileID")
	start_address = Column(Integer, name = "StartAddress")
	end_address = Column(Integer, name = "EndAddress")
	flag = Column(Integer, name = "Flag")
	function_address = Column(Integer, name = "FunctionAddress")
	block_type = Column(Integer, name = "BlockType")
	name = Column(String, name = "Name")
	disasm_lines = Column(String, name = "DisasmLines")
	fingerprint = Column(String, name = "Fingerprint")

	def __init__(self):
		pass

	def __repr__(self):
		return "<OneLocationInfo('%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s', '%s')>" % (self.file_id, 
								self.start_address, 
								self.end_address, 
								self.flag, 
								self.function_address, 
								self.block_type, 
								self.name, 
								self.disasm_lines, 
								self.fingerprint)


class TargetOneLocationInfo(Base):
	__tablename__='OneLocationInfo'
	__table_args__={'schema': 'Target'}

	id = Column(Integer, primary_key=True)
	file_id = Column(String, name = "FileID")
	start_address = Column(Integer, name = "StartAddress")
	end_address = Column(Integer, name = "EndAddress")
	flag = Column(Integer, name = "Flag")
	function_address = Column(Integer, name = "FunctionAddress")
	block_type = Column(Integer, name = "BlockType")
	name = Column(String, name = "Name")
	disasm_lines = Column(String, name = "DisasmLines")
	fingerprint = Column(String, name = "Fingerprint")

	def __init__(self):
		pass

	def __repr__(self):
		return "<OneLocationInfo('%d', '%d', '%d', '%d', '%d', '%d', '%s', '%s', '%s')>" % (self.file_id, 
								self.start_address, 
								self.end_address, 
								self.flag, 
								self.function_address, 
								self.block_type, 
								self.name, 
								self.disasm_lines, 
								self.fingerprint)



class SourceMapInfo(Base):
	__tablename__='MapInfo'
	__table_args__={'schema': 'Source'}

	id = Column(Integer, primary_key=True)
	file_id = Column(Integer, name = "FileID")
	
	type = Column(Integer, name = "Type")
	src_block = Column(Integer, name = "SrcBlock")
	src_block_end = Column(Integer, name = "SrcBlockEnd")
	dst = Column(Integer, name = "Dst")

	def __init__(self):
		pass

	def __repr__(self):
		return "<MapInfo('%d', '%d', '%d', '%d', '%d', '%d')>" % (self.file_id, 
								self.type, 
								self.src_block, 
								self.src_block_end, 
								self.dst)


class TargetMapInfo(Base):
	__tablename__='MapInfo'
	__table_args__={'schema': 'Target'}

	id = Column(Integer, primary_key=True)
	file_id = Column(Integer, name = "FileID")
	
	type = Column(Integer, name = "Type")
	src_block = Column(Integer, name = "SrcBlock")
	src_block_end = Column(Integer, name = "SrcBlockEnd")
	dst = Column(Integer, name = "Dst")

	def __init__(self):
		pass

	def __repr__(self):
		return "<MapInfo('%d', '%d', '%d', '%d', '%d', '%d')>" % (self.file_id, 
								self.type, 
								self.src_block, 
								self.src_block_end, 
								self.dst)


class Database:
	DebugLevel = 2
	UseAttach=True
	def __init__(self, filename):
		echo = False
		if self.DebugLevel > 2:
			echo = True

		if self.UseAttach:
			engine=create_engine('sqlite://',echo=False)
			engine.execute("ATTACH DATABASE '%s' AS Diff;" % filename)

			self.Session=sessionmaker()
			self.Session.configure(bind=engine)	
			self.SessionInstance = self.Session()
			
			metadata=MetaData(engine)

			type_map={}
			for file_list in self.SessionInstance.query(FileList).all():
				if type_map.has_key(file_list.type):
					continue

				type_map[file_list.type]=1

				query="ATTACH DATABASE '%s' AS %s;" % (file_list.filename,file_list.type)
				engine.execute(query)

		else:

			engine = create_engine('sqlite:///' + filename, echo = echo)
			self.metadata=MetaData(engine)
			self.Session=sessionmaker()
			self.Session.configure(bind=engine)	
			self.SessionInstance = self.Session()

			self.SessionInstancesMap={}
			for file_list in self.SessionInstance.query(FileList).all():
				filename=self.GetFilename(file_list.filename)
		
				engine = create_engine('sqlite:///' + filename, echo = echo)
				metadata=Base.metadata
				metadata.create_all(engine)

				self.Session=sessionmaker()
				self.Session.configure(bind=engine)	
				self.SessionInstancesMap[file_list.type] = self.Session()

			if not self.SessionInstancesMap.has_key('Source'):
				self.SessionInstancesMap['Source']=self.SessionInstance
			if not self.SessionInstancesMap.has_key('Target'):
				self.SessionInstancesMap['Target']=self.SessionInstance

	def GetFilename(self,filename):
		dirname=os.path.dirname(filename)
		if not os.path.isfile(filename):
			filename=os.path.join(dirname,os.path.basename(file_list.filename))

		if not os.path.isfile(filename):
			if file_list.filename[-4:].lower()!='.idb':
				idb_filename = file_list.filename[0:len(file_list.filename)] + '.idb'
				filename = idb_filename

		if not os.path.isfile(filename):
			if file_list.filename[-4:].lower()!='.idb':
				filename=os.path.join(dirname,os.path.basename(idb_filename))

		return filename

	def GetOneLocationInfo(self):
		return self.SessionInstance.query(OneLocationInfo).all()

	def GetOneLocationInfoCount(self):
		return self.SessionInstance.query(OneLocationInfo).count()

	def GetFunctionMatchInfo(self):
		return self.SessionInstance.query(FunctionMatchInfo).all()

	def GetFunctionMatchInfoCount(self):
		return self.SessionInstance.query(FunctionMatchInfo).count()

	def GetBBMatchInfo(self):
		SourceFunctionOneLocationInfo=aliased(SourceOneLocationInfo,name='SourceFunctionOneLocationInfo')
		TargetFunctionOneLocationInfo=aliased(TargetOneLocationInfo,name='TargetFunctionOneLocationInfo')

		query=self.SessionInstance.query(MatchMap,SourceOneLocationInfo,SourceFunctionOneLocationInfo,TargetOneLocationInfo,TargetFunctionOneLocationInfo).filter(MatchMap.match_rate < 100)
		query=query.outerjoin(SourceOneLocationInfo, MatchMap.source_address==SourceOneLocationInfo.start_address)
		query=query.outerjoin(SourceFunctionOneLocationInfo, SourceOneLocationInfo.function_address==SourceFunctionOneLocationInfo.start_address)
		query=query.outerjoin(TargetOneLocationInfo, MatchMap.target_address==TargetOneLocationInfo.start_address)
		query=query.outerjoin(TargetFunctionOneLocationInfo, TargetOneLocationInfo.function_address==TargetFunctionOneLocationInfo.start_address)
		matches=query.all()

		TmpMatchMap=aliased(MatchMap,name='TmpMatchMap')
		TmpTargetFunctionOneLocationInfo=aliased(TargetOneLocationInfo,name='TmpTargetOneLocationInfo')
		TmpSourceFunctionOneLocationInfo=aliased(SourceOneLocationInfo,name='TmpSourceFunctionOneLocationInfo')

		source_non_matched=[]
		stmt=exists().where(SourceOneLocationInfo.start_address==MatchMap.source_address)
		query=self.SessionInstance.query(SourceOneLocationInfo,SourceFunctionOneLocationInfo,TmpTargetFunctionOneLocationInfo).filter(SourceOneLocationInfo.fingerprint!='').filter(~stmt)
		query=query.outerjoin(SourceFunctionOneLocationInfo, SourceOneLocationInfo.function_address==SourceFunctionOneLocationInfo.start_address)
		query=query.outerjoin(TmpMatchMap, SourceOneLocationInfo.function_address==TmpMatchMap.source_address)
		query=query.outerjoin(TmpTargetFunctionOneLocationInfo, TmpMatchMap.target_address==TmpTargetFunctionOneLocationInfo.start_address)

		for ret in query.all():
			source_non_matched.append(ret)
		
		target_non_matched=[]
		stmt=exists().where(TargetOneLocationInfo.start_address==MatchMap.source_address)
		query=self.SessionInstance.query(TargetOneLocationInfo,TargetFunctionOneLocationInfo,TmpSourceFunctionOneLocationInfo).filter(TargetOneLocationInfo.fingerprint!='').filter(~stmt)
		query=query.outerjoin(TargetFunctionOneLocationInfo, TargetOneLocationInfo.function_address==TargetFunctionOneLocationInfo.start_address)
		query=query.outerjoin(TmpMatchMap, TargetOneLocationInfo.function_address==TmpMatchMap.target_address)
		query=query.outerjoin(TmpSourceFunctionOneLocationInfo, TmpMatchMap.source_address==TmpSourceFunctionOneLocationInfo.start_address)

		try:
			for ret in query.all():
				target_non_matched.append(ret)
		except:
			pass

		return [matches,source_non_matched,target_non_matched]

	def GetBlockName(self, file_id, address):
		for one_location_info in self.SessionInstance.query(OneLocationInfo).filter_by(file_id=file_id, start_address=address).all():
			return one_location_info.name
		return ""

	def GetFunctionDisasmLinesMapOrig(self, file_id, function_address):
		disasms={}
		for one_location_info in self.SessionInstance.query(OneLocationInfo).filter_by(file_id=file_id, function_address=function_address).all():
			disasms[one_location_info.start_address] = one_location_info.disasm_lines
		return disasms

	def GetFunctionDisasmLines(self, type, function_address):
		disasms={}
		bb_addresses = [ function_address ]
		links = {}

		if self.UseAttach:
			if type=='Source':
				map_info=SourceMapInfo
				one_location_info=SourceOneLocationInfo	
			else:
				map_info=TargetMapInfo
				one_location_info=TargetOneLocationInfo
			session=self.SessionInstance
		else:
			map_info=MapInfo
			one_location_info=OneLocationInfo	
			session=self.SessionInstancesMap[type]
		
		for bb_address in bb_addresses:
			for ret in session.query(map_info).filter_by(src_block=bb_address, type = CREF_FROM).all():
				if not ret.dst in bb_addresses:
					bb_addresses.append(ret.dst)

				if not links.has_key(bb_address):
					links[bb_address]=[]
				links[bb_address].append(ret.dst)

		for bb_address in bb_addresses:
			try:
				for ret in session.query(one_location_info).filter_by(start_address=bb_address).all():
					disasms[ret.start_address] = ret.disasm_lines
			except:
				pass

		return (disasms,links)

	def GetFunctionBlockAddresses(self, type, function_address):
		bb_addresses = [ function_address ]
		file_id=1

		if self.UseAttach:
			if type=='Source':
				map_info=SourceMapInfo
				one_location_info=SourceOneLocationInfo	
			else:
				map_info=TargetMapInfo
				one_location_info=TargetOneLocationInfo
			session=self.SessionInstance
		else:
			map_info=MapInfo
			one_location_info=OneLocationInfo	
			session=self.SessionInstancesMap[type]

		for bb_address in bb_addresses:
			for ret in session.query(map_info).filter_by(file_id=file_id, src_block=bb_address, type = CREF_FROM).all():
				if not ret.dst in bb_addresses:
					bb_addresses.append(ret.dst)

		block_range_addresses = []
		for bb_address in bb_addresses:
			for ret in session.query(one_location_info).filter_by(file_id=file_id, start_address=bb_address).all():
				block_range_addresses.append((ret.start_address, ret.end_address))
		return block_range_addresses

	def GetMatchMapForAddresses(self, file_id, bb_addresses):
		match_hash = {}
		for bb_address in bb_addresses:
			if file_id == 1:
				for match_map in self.SessionInstance.query(MatchMap).filter_by(source_address=bb_address).all():
					match_hash[ match_map.source_address ] = (match_map.target_address, match_map.match_rate)			
			else:
				for match_map in self.SessionInstance.query(MatchMap).filter_by(target_address=bb_address).all():
					match_hash[ match_map.target_address ] = (match_map.source_address, match_map.match_rate)
		return match_hash

	def GetMatchMapForFunction(self, file_id, function_address):
		match_hash = {}
		for match_map in self.SessionInstance.query(MatchMap).filter(MatchMap.source_address.in_(self.SessionInstance.query(OneLocationInfo.start_address).filter_by(file_id = file_id, function_address=function_address))).all():
			match_hash[ match_map.source_address ] = (match_map.target_address, match_map.match_rate)
		return match_hash

	def GetDisasmComparisonTable(self, source_data, target_data, match_map):
		left_addresses = source_data.keys()
		left_addresses.sort()
	
		right_addresses = target_data.keys()
		right_addresses.sort()

		right_addresses_index={}	
		index = 0
		for address in right_addresses:
			right_addresses_index[address] = index
			index += 1
		disasm_table={}
		Checkedright_addresses={}
		left_address_index = 0
		for left_address in left_addresses:
			right_address_index = None
			match_rate = 0
			maximum_index = left_address_index
			if match_map.has_key(left_address):
				right_address = match_map[ left_address ][0]
				match_rate = match_map[ left_address ][1]
				Checkedright_addresses[ right_address ] = 1
				
				if right_addresses_index.has_key(right_address):
					right_address_index = right_addresses_index[right_address]
					if self.DebugLevel > 2:
						print left_address_index, right_address_index
					
					if left_address_index > right_address_index:
						maximum_index = left_address_index
					elif left_address_index < right_address_index:
						maximum_index = right_address_index
	
			while disasm_table.has_key(maximum_index):
				maximum_index += 1
	
			disasm_table[ maximum_index ] = (left_address_index, right_address_index, match_rate)
			left_address_index += 1
	
		for right_address in right_addresses_index:
			if not Checkedright_addresses.has_key(right_address):
				right_address_index = right_addresses_index[right_address]
				
				new_disasm_table = {}
				if disasm_table.has_key(right_address_index):
					for index in disasm_table.keys():
						if index >= right_address_index:
							new_disasm_table[ index + 1 ] = disasm_table[ index ]
						else:
							new_disasm_table[ index ] = disasm_table[ index ]
					new_disasm_table[right_address_index] = (None, right_address_index, 0)
					disasm_table = new_disasm_table
				else:
					disasm_table[right_address_index] = (None, right_address_index, 0)
	
		if self.DebugLevel > 2:
			print 'disasm_table:'
			for (index, (left_address_index, right_address_index, match_rate)) in disasm_table.items():
				print left_address_index, right_address_index, match_rate

		indexes = disasm_table.keys()
		indexes.sort()
	
		disasm_blocks=[]
	
		for index in indexes:
			(left_address_index, right_address_index, match_rate) = disasm_table[index]
	
			left_address = 0
			right_address = 0
			if left_address_index != None :
				left_address = left_addresses[ left_address_index ]
				
			if right_address_index != None :
				right_address = right_addresses[ right_address_index ]
	
			if self.DebugLevel > 2:
				print index, ':', left_address_index, hex(left_address), right_address_index, hex(right_address)
	
			left_lines=()
			right_lines=()
	
			if source_data.has_key(left_address):
				left_lines = source_data[ left_address ].split('\n')
	
			if target_data.has_key(right_address):
				right_lines = target_data[ right_address ].split('\n')
		
			if self.DebugLevel > 2:
				print 'Split Lines'
				print left_lines, right_lines

			disasm_blocks.append((left_address, left_lines, right_address, right_lines, match_rate))
		return disasm_blocks

	def GetDisasmLinesSideBySide(self, left_lines, right_lines):
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

			disasm_lines.append((left_line, right_line))
			i += 1
		return disasm_lines

	def GetAlignedDisasmText(self, disasm_lines):
		disasm_text = ''
		maximum_left_line_length = 0
		for (left_line, right_line) in disasm_lines:
			if len(left_line) > maximum_left_line_length:
				maximum_left_line_length = len(left_line)
		
		maximum_left_line_length += 10
		for (left_line, right_line) in disasm_lines:
			space_len = maximum_left_line_length - len(left_line)
			disasm_text += left_line + " " * space_len + right_line + '\n'
		return disasm_text

	def GetDisasmText(self, comparison_table):
		disasm_lines = []
		for (left_address, left_lines, right_address, right_lines, match_rate) in comparison_table:
			disasm_lines += self.GetDisasmLinesSideBySide(left_lines, right_lines)

		return self.GetAlignedDisasmText(disasm_lines)

	def GetDisasmComparisonTextByFunctionAddress(self, source_function_address, target_function_address):
		(source_disasms,source_links) = self.GetFunctionDisasmLines("Source", source_function_address)
		(target_disasms,target_links) = self.GetFunctionDisasmLines("Target", target_function_address)
		
		match_map = self.GetMatchMapForAddresses(1, source_disasms.keys())
		return self.GetDisasmComparisonTable(source_disasms, target_disasms, match_map)

	def GetBlockAddressMatchTableByFunctionAddress(self, source_function_address, target_function_address):
		source_bb_addresses = self.GetFunctionBlockAddresses("Source", source_function_address)
		target_bb_addresses = self.GetFunctionBlockAddresses("Target", target_function_address)

		source_block_start_addresses = []
		for (start_address, end_address) in source_bb_addresses:
			source_block_start_addresses.append(start_address)
		match_map = self.GetMatchMapForAddresses(1, source_block_start_addresses)

		source_address_match_rate_hash = {}
		target_address_match_rate_hash = {}
		for (source_address, (target_address, match_rate)) in match_map.items():
			source_address_match_rate_hash[ source_address ] = match_rate
			target_address_match_rate_hash[ target_address ] = match_rate

		source_address_match_rate_infos = []
		for (start_address, end_address) in source_bb_addresses:
			match_rate = 0
			if source_address_match_rate_hash.has_key(start_address):
				match_rate = source_address_match_rate_hash[ start_address ] 
			source_address_match_rate_infos.append((start_address, end_address+1, match_rate))

		target_address_match_rate_infos = []
		for (start_address, end_address) in target_bb_addresses:
			match_rate = 0
			if target_address_match_rate_hash.has_key(start_address):
				match_rate = target_address_match_rate_hash[ start_address ] 
			target_address_match_rate_infos.append((start_address, end_address+1, match_rate))

		return (source_address_match_rate_infos, target_address_match_rate_infos)

	def GetBlockMatches(self, source_function_address, target_function_address):
		source_bb_addresses = self.GetFunctionBlockAddresses("Source", source_function_address)
		target_bb_addresses = self.GetFunctionBlockAddresses("Target", target_function_address)

		source_block_start_addresses = []
		for (start_address, end_address) in source_bb_addresses:
			source_block_start_addresses.append(start_address)
		match_map = self.GetMatchMapForAddresses(1, source_block_start_addresses)

		return match_map.items()

	def Commit(self):
		self.SessionInstance.commit()

if __name__ == '__main__':
	import sys
	filename = sys.argv[1]

	database = Database(filename)
	for function_match_info in database.GetFunctionMatchInfo():
		if function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
			#print function_match_info.id, function_match_info.source_file_id, function_match_info.target_file_id, function_match_info.end_address, 
			
			print "%s\t%s\t%s\t%s\t%s%%\t%d\t%d\t%d\t%d\t%d\t%d" % (function_match_info.source_function_name,
													function_match_info.target_function_name,
													str(function_match_info.block_type),
													str(function_match_info.type),
													str(function_match_info.match_rate),
													function_match_info.match_count_for_the_source, 
													function_match_info.non_match_count_for_the_source, 
													function_match_info.match_count_with_modificationfor_the_source, 
													function_match_info.match_count_for_the_target, 
													function_match_info.non_match_count_for_the_target, 
													function_match_info.match_count_with_modification_for_the_target)

			#print database.GetFunctionDisasmLines(function_match_info.source_file_id, function_match_info.source_address)
			#print database.GetMatchMapForFunction(function_match_info.source_file_id, function_match_info.source_address)
			#disasm_table = database.GetDisasmComparisonTextByFunctionAddress(function_match_info.source_address, function_match_info.target_address)
			#print database.GetDisasmText(disasm_table)
