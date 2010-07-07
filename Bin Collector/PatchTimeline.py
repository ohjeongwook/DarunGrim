from FileStore import *
import PatchDatabaseWrapper

class Analyzer:
	DebugLevel = 0
	def __init__( self, database_name = None, database = None ):
		if database_name:
			self.DatabaseName = database_name
			self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )
		elif database:
			self.Database = database

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

	def GetPatchHistory( self, filename ):
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
				patch_infos_by_patch_name[patch_name].append( entry.GetVersionDetail() )

		sorted_patch_infos = []
		patch_names = patch_infos_by_patch_name.keys()
		patch_names.sort()
		patch_names.reverse()
		for patch_name in patch_names:
			sorted_patch_infos.append( ( patch_name, patch_infos_by_patch_name[patch_name] ) )

		return sorted_patch_infos

	def GetFileHistory( self, filename ):
		return self.Database.GetFileByFileName( filename )

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

	def GetPatchPairsForAnalysis( self, filename = None, id = None, patch_name = None ):
		file_patch_info = self.GetPatchHistory( filename )
		target_file_entry = None

		if id:
			file_entry = self.Database.GetFileByID( id )
			if file_entry and len( file_entry ) > 0:
				target_file_entry = file_entry[0].GetVersionDetail()
				print 'target_file_entry=', target_file_entry

		patch_pairs_for_analysis = []
		for ( current_patch_name, file_entries ) in file_patch_info:		
			if patch_name and current_patch_name != patch_name:
				continue

			maximum_point = 0
			maximum_entry = None

			if target_file_entry:
				target_file_entries = [ target_file_entry ]
			else:
				target_file_entries = file_entries

			for file_entry in target_file_entries:
				( matched_patch_name, matched_file_entry, match_point ) = self.FindPatchTarget( file_patch_info, current_patch_name, file_entry )
				if match_point > maximum_point:
					maximum_entry = ( matched_patch_name, file_entry, matched_file_entry, match_point )
					maximum_point = match_point

			if maximum_entry:
				( matched_patch_name, file_entry, matched_file_entry, match_point ) = maximum_entry
				if self.DebugLevel > 2:
					print '='*80
					print current_patch_name
					print file_entry
					print matched_patch_name
					print matched_file_entry
				patch_pairs_for_analysis.append( ( current_patch_name, file_entry, matched_patch_name, matched_file_entry ) )

		return patch_pairs_for_analysis

if __name__ == '__main__':
	import sys
	filename = sys.argv[1]

	test = [ 2 ]
	if 1 in test:
		#analyzer = Analyzer( database_name = r'..\UI\Web\index.db' )
		analyzer = Analyzer( database_name = r'adobe.db' )
		print 'filename=',filename
		for row in analyzer.GetPatchHistory( filename ):
			( patch_name, patch_infos ) = row
			print patch_name
			for patch_info in patch_infos:
				print '-'*50
				for (key,value) in patch_info.items():
					print '\t',key,value
	
	elif 2 in test:
		analyzer = Analyzer( database_name = r'adobe.db' )
		
		print 'filename=',filename
		for row in analyzer.GetFileHistory( filename ):
			print row
