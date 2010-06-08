import sys
sys.path.append(r'T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\Bin')
sys.path.append(r'..')
sys.path.append(r'..\Diff Inspector')
import os

import PatchTimeline
import DarunGrimEngine
import PatchDatabaseWrapper
import DarunGrimAnalyzers
import DarunGrimDatabaseWrapper

class Manager:
	DebugLevel = 3

	def __init__( self, databasename = 'test.db', output_directory = r'C:\mat\Projects\DGFs',ida_path = r'C:\Program Files (x86)\IDA\idag.exe' ):
		self.DatabaseFilename = databasename
		self.OutputDirectory = output_directory
		self.IDAPath = ida_path
		if not os.path.isdir( self.OutputDirectory ):
			os.makedirs( self.OutputDirectory )
		
		self.PatchTimelineAnalyzer = PatchTimeline.Analyzer( self.DatabaseFilename )

	def InitMSFileDiff( self, patch_name, filename ):
		print 'Analyzing', patch_name, filename
		for ( target_patch_name, target_file_entry, source_patch_name, source_file_entry ) in self.PatchTimelineAnalyzer.GetPatchPairsForAnalysis( filename, patch_name ):
			print '='*80
			print target_patch_name,source_patch_name
	
			source_filename = source_file_entry['full_path']
			target_filename = target_file_entry['full_path']
			print source_patch_name, source_filename, target_patch_name, target_filename 
			self.InitFileDiff( source_patch_name, source_filename, target_patch_name, target_filename )

	def InitFileDiffByID( self, source_id, target_id, databasename = None ):
		database = PatchDatabaseWrapper.Database( self.DatabaseFilename )
		source_file_entries = database.GetFileByID( source_id )
		print 'source', source_id, source_file_entries

		source_patch_name = 'None'
		if source_file_entries[0].downloads and source_file_entries[0].downloads.patches.name:
			source_patch_name = source_file_entries[0].downloads.patches.name
		source_filename = source_file_entries[0].full_path

		target_file_entries = database.GetFileByID( target_id )
		print target_id, target_file_entries 

		target_patch_name = 'None'
		if target_file_entries[0].downloads and target_file_entries[0].downloads.patches.name:
			target_patch_name = target_file_entries[0].downloads.patches.name
		target_filename = target_file_entries[0].full_path

		if not databasename:
			databasename = str( source_id ) + '_' + str( target_id ) + ".dgf"
		databasename = self.InitFileDiff( source_patch_name, source_filename, target_patch_name, target_filename, databasename )
		return databasename

	def InitFileDiff( self, source_patch_name, source_filename, target_patch_name, target_filename, databasename = None ):
		if self.DebugLevel > 2:
			print '='*80
			print source_patch_name
			print source_filename
			print target_patch_name
			print target_filename
			print databasename
		base_filename = os.path.basename( source_filename )
		dot_pos = base_filename.find('.')
		if dot_pos >= 0:
			base_filename = base_filename[:dot_pos]
		
		prefix = target_patch_name + '-' + source_patch_name + '-' + base_filename

		if not databasename:
			databasename = prefix + ".dgf"
		full_databasename =  os.path.join( self.OutputDirectory , databasename )
		log_filename = os.path.join( self.OutputDirectory , prefix + ".log" )

		if os.path.isfile( databasename ) and os.path.getsize( databasename ) > 0:
			print 'Already analyzed',databasename
		else:
			if self.DebugLevel > 2:
				print 'source_filename',source_filename
				print 'target_filename',target_filename
				print 'databasename',databasename
			DarunGrimEngine.DiffFile( source_filename, target_filename, full_databasename, log_filename, self.IDAPath )
			self.UpdateSecurityImplicationsScore( full_databasename )
		return databasename

	def UpdateSecurityImplicationsScore( self, databasename ):
		database = DarunGrimDatabaseWrapper.Database( databasename )
		pattern_analyzer = DarunGrimAnalyzers.PatternAnalyzer()
		for function_match_info in database.GetFunctionMatchInfo():
			if function_match_info.non_match_count_for_the_source > 0 or \
				function_match_info.non_match_count_for_the_target > 0 or \
				function_match_info.match_count_with_modificationfor_the_source > 0:
	
				function_match_info.security_implications_score = pattern_analyzer.GetSecurityImplicationsScore( 
											databasename,
											function_match_info.source_address, 
											function_match_info.target_address )
				print function_match_info.security_implications_score
		database.Commit()

	def InitMSFileDiffAll( self ):
		for ( patch_name, filename ) in self.PatchTimelineAnalyzer.GetPatchFileNamePairs():
			self.InitMSFileDiff( patch_name, filename )

if __name__ == '__main__':
	file_differ = Manager()
	file_differ.InitMSFileDiffAll()

