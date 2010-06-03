import sys
sys.path.append(r'T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\Bin')
sys.path.append(r'..')
import os

import PatchTimeline
import DarunGrimEngine
import PatchDatabaseWrapper

class Manager:
	DebugLevel = 3

	def __init__( self, database_name = 'test.db', output_directory = r'C:\mat\Projects\DGFs',ida_path = r'C:\Program Files (x86)\IDA\idag.exe' ):
		self.DatabaseFilename = database_name
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

	def InitFileDiffByID( self, source_id, target_id ):
		database = PatchDatabaseWrapper.Database( self.DatabaseFilename )
		source_file_entries = database.GetFileByID( source_id )
		print source_id, source_file_entries

		source_patch_name = source_file_entries[0].downloads.patches.name
		source_filename = source_file_entries[0].full_path

		target_file_entries = database.GetFileByID( target_id )
		print target_id, target_file_entries 

		target_patch_name = target_file_entries[0].downloads.patches.name
		target_filename = target_file_entries[0].full_path
		storage_filename = self.InitFileDiff( source_patch_name, source_filename, target_patch_name, target_filename )
		return storage_filename

	def InitFileDiff( self, source_patch_name, source_filename, target_patch_name, target_filename, storage_filename = None ):
		if self.DebugLevel > 2:
			print '='*80
			print source_patch_name
			print source_filename
			print target_patch_name
			print target_filename
			print storage_filename
		base_filename = os.path.basename( source_filename )
		dot_pos = base_filename.find('.')
		if dot_pos >= 0:
			base_filename = base_filename[:dot_pos]
		
		prefix = target_patch_name + '-' + source_patch_name + '-' + base_filename

		if not storage_filename:
			storage_filename =  os.path.join( self.OutputDirectory , prefix + ".dgf" )
		log_filename = os.path.join( self.OutputDirectory , prefix + ".log" )

		if os.path.isfile( storage_filename ) and os.path.getsize( storage_filename ) > 0:
			print 'Already analyzed',storage_filename
		else:
			if self.DebugLevel > 2:
				print 'source_filename',source_filename
				print 'target_filename',target_filename
				print 'storage_filename',storage_filename
			DarunGrimEngine.DiffFile( source_filename, target_filename, storage_filename, log_filename, self.IDAPath )
		return storage_filename

	def InitMSFileDiffAll( self ):
		for ( patch_name, filename ) in self.PatchTimelineAnalyzer.GetPatchFileNamePairs():
			self.InitMSFileDiff( patch_name, filename )

if __name__ == '__main__':
	file_differ = Manager()
	file_differ.InitMSFileDiffAll()

