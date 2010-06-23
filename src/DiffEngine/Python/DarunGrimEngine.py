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
		
	def DiffFile( self, StorageFilename, LogFilename ):
		print 'Comparing',TheSourceFilename,TheTargetFilename
		StorageFilename = os.path.join( os.getcwd(), str(StorageFilename) )
		LogFilename = os.path.join( os.getcwd(), str(LogFilename) )

		self.DarunGrim.GenerateDB(
			StorageFilename, LogFilename, 
			0, 0,
			0, 0)
		self.DarunGrim.Analyze()

	def SyncIDA( self ):
		self.DarunGrim.AcceptIDAClientsFromSocket()

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
