from FileStore import *
import PatchDatabaseWrapper

class Analyzer:
	DebugLevel = 0
	def __init__( self, database_name ):
		self.DatabaseName = database_name
		self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )

	def GetPatchFileNamePairs( self ):
		patch_file_name_pairs = []
		for patch in self.Database.GetPatches():
			if self.DebugLevel > 2:
				print patch.name
			filenames = {}
			for download in self.Database.GetDownloadByPatchID( patch.id ):
				if self.DebugLevel > 2:
					print '\t',download.filename
				for fileindex in self.Database.GetFileByDownloadID( download.id ):
					if self.DebugLevel > 2:
						print '\t\t',fileindex.filename
					filenames[fileindex.filename] = 1
			for filename in filenames.keys():
				patch_file_name_pairs.append( ( patch.name, filename ) )
		return patch_file_name_pairs

	def GetPatchInfo( self, filename ):
		patch_infos_by_patch_name = {}
		
		process_patches = {}
		for entry in self.Database.GetFileByFileName( filename ):
			patch_name = 'Default'
			if entry.downloads and entry.downloads.patches:
				patch_name = entry.downloads.patches.name
		
			if not patch_infos_by_patch_name.has_key(patch_name):
				patch_infos_by_patch_name[patch_name] = []
				
			if not process_patches.has_key( entry.version_string ):
				process_patches[entry.version_string] = 1
				(os_string, sp_string, os_type, os_code, build_number) = self.ParseVersionString( entry.version_string )
				patch_infos_by_patch_name[patch_name].append( (entry.id, entry.full_path,os_string, sp_string, os_type, os_code, build_number) )

		patch_infos = []
		patch_names = patch_infos_by_patch_name.keys()
		patch_names.sort()
		patch_names.reverse()
		for patch_name in patch_names:
			file_entries = []
			for (id, full_path, os_string, sp_string, os_type, os_code, build_number) in patch_infos_by_patch_name[patch_name]:
				file_entry = {}
				file_entry['id'] = id
				file_entry['full_path'] = full_path
				file_entry['os_code'] = os_code
				file_entry['os_string'] = os_string
				file_entry['sp_string'] = sp_string
				file_entry['os_type'] = os_type
				file_entry['build_number'] = build_number
				file_entries.append( file_entry )
			patch_infos.append( ( patch_name, file_entries ) )
		return patch_infos

	def ParseVersionString( self, version_string ):
		main_parts = version_string.split( ' ' )

		identifier = ''
		version = ''
		if len( main_parts ) == 1:
			version = main_parts[0]
		elif len( main_parts ) == 2:
			( version, identifier ) = main_parts

		#### Version
		version_parts = version.split('.')
		
		os_code = ''
		build_number = ''
		if len( version_parts ) > 3:
			os_code = version_parts[0]+'.'+version_parts[1]+'.'+version_parts[2]
			build_number = version_parts[3]

		
		#### Distro
		dot_pos = identifier.find(".")
		distro=''
		if dot_pos >= 0:
			distro = identifier[:dot_pos]
		distro = distro[1:]
		distro_parts = distro.split( '_' )
		os_string = ''
		sp_string = ''
		os_type = ''
		if len( distro_parts ) == 2:
			os_string = distro_parts[0]
			if os_string == 'xpsp2':
				os_string = 'xpsp'
				sp_string = 'sp2'
			elif os_string == 'xpclnt':
				os_string = 'xpsp'

		elif len( distro_parts ) == 3:
			os_string = distro_parts[0]
			sp_string = distro_parts[1]
			os_type = distro_parts[2]

		return (os_string, sp_string, os_type, os_code, build_number)

	def DumpPatchInfos( self, patch_infos ):
		version_strings = patch_infos.keys()
		version_strings.sort()

		for version_string in version_strings:
			patch_name = patch_infos[version_string]
			if self.DebugLevel > 2:
				print patch_name, version_string
			(os_string, sp_string, os_type, os_code, build_number) = ParseVersionString( version_string )
			if self.DebugLevel > 2:
				print '\t',os_string, sp_string, os_type, os_code, build_number

	def FindPatchTarget( self, file_patch_info, target_patch_name, target_file_entry ):
		maximum_match_patch_name = None
		maximum_match_file_entry = None
		maximum_point = 0
		index = 0
		for (patch_name, file_entries) in file_patch_info:
			if self.DebugLevel > 2:
				print 'Comparing',target_patch_name,patch_name
			if cmp( target_patch_name, patch_name ) > 0 :
				if self.DebugLevel > 2:
					print 'Check',patch_name

				for file_entry in file_entries:
					weight = len(file_patch_info)
					point = weight * (len(file_patch_info) - index) * 30
					
					if not target_file_entry.has_key('os_code') or ( target_file_entry[ 'os_code' ] == file_entry[ 'os_code' ] ):
						point += weight * 20
						if not target_file_entry.has_key('os_string') or ( target_file_entry[ 'os_string' ] == file_entry[ 'os_string' ] ):
							point += weight * 10
							if not target_file_entry.has_key('sp_string') or ( target_file_entry[ 'sp_string' ] == file_entry[ 'sp_string' ] ):
								point += weight * 5
								if not target_file_entry.has_key('os_type') or ( target_file_entry[ 'os_type' ] == file_entry[ 'os_type' ] ):
									point += weight

					if point > maximum_point:
						if self.DebugLevel > 2:
							print 'Check',file_entry,point
						maximum_match_patch_name = patch_name
						maximum_match_file_entry = file_entry
						maximum_point = point
			index += 1
		return ( maximum_match_patch_name, maximum_match_file_entry, maximum_point )

	def GetPatchPairsForAnalysis( self, filename, patch_name_to_check = None ):
		file_patch_info = self.GetPatchInfo( filename )
		patch_pairs_for_analysis = []
		for ( patch_name, file_entries ) in file_patch_info:		
			if patch_name_to_check and not patch_name in patch_name_to_check:
				continue

			maximum_point = 0
			maximum_entry = None
			
			for file_entry in file_entries:
				( matched_patch_name, matched_file_entry, match_point ) = self.FindPatchTarget( file_patch_info, patch_name, file_entry )
				if match_point > maximum_point:
					maximum_entry = ( matched_patch_name, file_entry, matched_file_entry, match_point )
					maximum_point = match_point

			if maximum_entry:
				( matched_patch_name, file_entry, matched_file_entry, match_point ) = maximum_entry
				if self.DebugLevel > 2:
					print '='*80
					print patch_name
					print file_entry
					print matched_patch_name
					print matched_file_entry
				patch_pairs_for_analysis.append( ( patch_name, file_entry, matched_patch_name, matched_file_entry ) )

		return patch_pairs_for_analysis
