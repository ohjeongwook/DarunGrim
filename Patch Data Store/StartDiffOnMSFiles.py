from PatchAnalyzer import *

for file in ('netapi32.dll','wkssvc.dll'):
	patch_analyzer = PatchSorter( 'test.db', file )
	for ( patch_name, file_entry, matched_patch_name, matched_file_entries ) in patch_analyzer.GetPatchPairsForAnalysis():
		print '='*80
		print patch_name, file_entry
		print matched_patch_name, matched_file_entries
		
