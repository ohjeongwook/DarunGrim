import sys
import DiffEngine
import os

def DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath = r'C:\Program Files (x86)\IDA\idag.exe' ):
	TheSourceFilename = str(TheSourceFilename)
	TheTargetFilename = str(TheTargetFilename)
	#print 'Comparing',TheSourceFilename,TheTargetFilename

	StorageFilename = os.path.join( os.getcwd(), str(StorageFilename) )
	LogFilename = os.path.join( os.getcwd(), str(LogFilename) )

	darun_grim = DiffEngine.DarunGrim()
	darun_grim.SetIDAPath( IDAPath )
	darun_grim.GenerateDB(
		StorageFilename, LogFilename, 
		TheSourceFilename, 0, 0,
		TheTargetFilename, 0, 0)
	darun_grim.Analyze()

if __name__ == '__main__':
	"""
	TheSourceFilename = sys.argv[1]
	TheTargetFilename = sys.argv[2]
	StorageFilename = sys.argv[3]

	LogFilename = 'test.log'

	IDAPath = r'C:\Program Files (x86)\IDA\idag.exe'
	DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath )
	"""
	
	ida_client_manager = DiffEngine.IDAClientManager()
	ida_client_manager.StartIDAListener( 1216 )
	raw_input( 'Press any key to continue...' )
