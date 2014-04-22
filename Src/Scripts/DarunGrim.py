import sys
import DiffEngine
import os

LogToStdout = 0x1
LogToDbgview = 0x2
LogToFile = 0x4
LogToIDAMessageBox = 0x8

class Differ:
	def __init__ ( self, SourceFilename, TargetFilename ):
		self.SourceFilename = str(SourceFilename)
		self.TargetFilename = str(TargetFilename)
		self.DarunGrim = DiffEngine.DarunGrim()
		self.DarunGrim.SetSourceFilename( self.SourceFilename )
		self.DarunGrim.SetTargetFilename( self.TargetFilename )
		self.DarunGrim.SetIDAPath( r'C:\Program Files (x86)\IDA\idag.exe' )

	def SetIDAPath( self, ida_path ):
		self.DarunGrim.SetIDAPath( ida_path )

	def DiffFile( self, storage_filename, log_filename, ida_log_filename_for_source = None, ida_logfilename_for_target = None ):
		storage_filename = os.path.join( os.getcwd(), str(storage_filename) )
		log_filename = os.path.join( os.getcwd(), str(log_filename) )

		self.DarunGrim.GenerateDB(
			storage_filename, log_filename, 
			ida_log_filename_for_source,
			ida_logfilename_for_target,
			0, 0,
			0, 0)
		self.DarunGrim.Analyze()

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

	src_filename = args[0]
	target_filename = args[1]
	result_filename = args[2]

	darun_grim = DiffEngine.DarunGrim()
	darun_grim.SetLogParameters(LogToStdout, 100, "");  
	darun_grim.DiffDatabaseFiles(src_filename, options.source_address, target_filename, options.target_address, result_filename)

