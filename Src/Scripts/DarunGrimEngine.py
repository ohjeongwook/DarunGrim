import sys
import DiffEngine
import os

LogToStdout = 0x1
LogToDbgview = 0x2
LogToFile = 0x4
LogToIDAMessageBox = 0x8

class Differ:
	def __init__ ( self, orig_filename, patched_filename ):
		self.OrigFilename = str(orig_filename)
		self.PatchedFilename = str(patched_filename)
		self.DarunGrim = DiffEngine.DarunGrim()
		self.DarunGrim.SetSourceFilename( self.OrigFilename )
		self.DarunGrim.SetTargetFilename( self.PatchedFilename )
		self.DarunGrim.SetIDAPath( r'C:\Program Files (x86)\IDA 6.6\idaq.exe' )
		self.DarunGrim.SetLogParameters(LogToStdout, 100, "")

	def SetIDAPath( self, ida_path ):
		self.DarunGrim.SetIDAPath( ida_path )

	def Start( self, dgf_output_filename, log_filename, ida_log_filename_for_source = None, ida_logfilename_for_target = None ):
		filename = os.path.join( os.getcwd(), str(dgf_output_filename) )
		log_filename = os.path.join( os.getcwd(), str(log_filename) )

		print 'dgf_output_filename:', dgf_output_filename
		#TODO: Fix
		self.DarunGrim.GenerateDGF(
			dgf_output_filename,
			log_filename, 
			ida_log_filename_for_source,
			ida_logfilename_for_target,
			0, 0,
			0, 0)
		self.DarunGrim.PerformDiff()

	def SyncIDA( self ):
		self.DarunGrim.AcceptIDAClientsFromSocket()
		
	def ShowAddresses( self, source_address, target_address ):
		self.DarunGrim.ShowAddresses( source_address, target_address )

	def ColorAddress( self, index, start_address, end_address, color ):
		self.DarunGrim.ColorAddress( index, start_address, end_address, color )

if __name__ == '__main__':
	from optparse import OptionParser

	parser = OptionParser()
	parser.add_option("-s", "--source_address", dest="source_address",
						help="Source function address", type="int", default=0, metavar="SOURCE_ADDRESS")
	parser.add_option("-t", "--target_address", dest="target_address",
						help="Target function address", type="int", default=0, metavar="TARGET_ADDRESS")

	(options, args) = parser.parse_args()

	orig_filename = args[0]
	patched_filename = args[1]
	dgf_output_filename = args[2]

	"""
	darun_grim = DiffEngine.DarunGrim()
	darun_grim.SetLogParameters(LogToStdout, 100, "")  

	darun_grim.PerformDiff(src_filename, options.source_address, target_filename, options.target_address, result_filename)
	"""

	differ=Differ(orig_filename, patched_filename)
	differ.Start( dgf_output_filename, "log.txt")