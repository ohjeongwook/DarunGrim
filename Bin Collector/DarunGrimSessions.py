import sys
sys.path.append(r'T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\Bin')
import PatchTimeline
import DarunGrimEngine
import os

class Manager:
	DebugLevel = 0

	def __init__( self, indexfile = 'test.db', output_directory = r'C:\mat\Projects\DGFs',ida_path = r'C:\Program Files (x86)\IDA\idag.exe' ):
		self.IndexFile = indexfile
		self.OutputDirectory = output_directory
		self.IDAPath = ida_path
		if not os.path.isdir( self.OutputDirectory ):
			os.makedirs( self.OutputDirectory )
		
		self.PatchTimelineAnalyzer = PatchTimeline.Analyzer( self.IndexFile )

	def InitMSFileDiff( self, patch_name, filename ):
		print 'Analyzing', patch_name, filename
		for ( patch_name, file_entry, matched_patch_name, matched_file_entries ) in self.PatchTimelineAnalyzer.GetPatchPairsForAnalysis( filename = filename, patch_name = patch_name ):
			print '='*80
			print patch_name,matched_patch_name
	
			source_filename = matched_file_entries['full_path']
			target_filename = file_entry['full_path']
			print patch_name, source_filename, matched_patch_name, target_filename 
			self.InitFileDiff( patch_name, source_filename, matched_patch_name, target_filename )

	def InitFileDiff( self, patch_name, source_filename, matched_patch_name, target_filename, storage_filename = None ):
		base_filename = os.path.basename( source_filename )
		print 'base_name', base_filename 
		dot_pos = base_filename.find('.')
		if dot_pos >= 0:
			base_filename = base_filename[:dot_pos]
		
		prefix = patch_name + '-' + matched_patch_name + '-' + base_filename

		if not storage_filename:
			storage_filename =  os.path.join( self.OutputDirectory , prefix + ".dgf" )
		LogFilename = os.path.join( self.OutputDirectory , prefix + ".log" )

		if os.path.isfile( storage_filename ) and os.path.getsize( storage_filename ) > 0:
			print 'Already analyzed',storage_filename
		else:
			if self.DebugLevel > 2:
				print 'source_filename',source_filename
				print 'target_filename',target_filename
				print 'storage_filename',storage_filename
			DarunGrimEngine.DiffFile( source_filename, target_filename, storage_filename, LogFilename, self.IDAPath )

	def InitMSFileDiffAll( self ):
		for ( patch_name, filename ) in self.PatchTimelineAnalyzer.GetPatchFileNamePairs():
			self.InitMSFileDiff( patch_name, filename )

if __name__ == '__main__':
	file_differ = Manager()
	file_differ.InitMSFileDiffAll()
