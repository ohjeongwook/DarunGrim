import sys
import DiffEngine
import os

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

	def LoadDiffResults( self, storage_filename ):
		storage_filename = os.path.join( os.getcwd(), str(storage_filename) )
		self.DarunGrim.LoadDiffResults( storage_filename )

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
	"""
	TheSourceFilename = sys.argv[1]
	TheTargetFilename = sys.argv[2]
	StorageFilename = sys.argv[3]

	LogFilename = 'test.log'

	IDAPath = r'C:\Program Files (x86)\IDA\idag.exe'
	DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath )
	"""
	
	"""
	ida_client_manager = DiffEngine.IDAClientManager()
	ida_client_manager.StartIDAListener( 1216 )
	"""
	
	darun_grim = DiffEngine.DarunGrim()
	storage_filename = os.path.join( os.getcwd(), str('test2.dgf') )
	darun_grim.AcceptIDAClientsFromSocket( storage_filename )
	raw_input( 'Press any key to continue...' )
