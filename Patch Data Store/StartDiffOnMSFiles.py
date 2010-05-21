import sys
sys.path.append(r'T:\mat\Projects\ResearchTools\Binary\StaticAnalysis\DarunGrim2\src\Bin')
from PatchAnalyzer import *
import DarunGrimEngine

OutputDirectory = 'DGFs'
IndexFile = 'test.db'
AnalysisTargetFiles = sys.argv[1:]

if not os.path.isdir( OutputDirectory ):
	os.makedirs( OutputDirectory )
	
patch_analyzer = PatchSorter( IndexFile )

for ( patch_name, filename ) in patch_analyzer.GetPatchFileNamePairs():
	print 'Analyzing', patch_name, filename
	for ( patch_name, file_entry, matched_patch_name, matched_file_entries ) in patch_analyzer.GetPatchPairsForAnalysis( filename, patch_name ):
		print '='*80
		#print patch_name, file_entry
		#print matched_patch_name, matched_file_entries
		print patch_name,matched_patch_name

		TheSourceFilename = matched_file_entries['full_path']
		TheTargetFilename = file_entry['full_path']

		base_filename = filename
		dot_pos = filename.find('.')
		if dot_pos >= 0:
			base_filename = filename[:dot_pos]
		
		prefix = patch_name + '-' + matched_patch_name + '-' + base_filename
		StorageFilename =  os.path.join( OutputDirectory , prefix + ".dgf" )
		LogFilename = os.path.join( OutputDirectory , prefix + ".log" )
		IDAPath = r'C:\Program Files (x86)\IDA\idag.exe'

		if os.path.isfile( StorageFilename ) and os.path.getsize( StorageFilename ) > 0:
			print 'Already analyzed',StorageFilename
		else:
			DarunGrimEngine.DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath )
