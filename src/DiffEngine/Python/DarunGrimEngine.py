import sys
import DiffEngine
import os

def DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath = r'C:\Program Files (x86)\IDA\idag.exe' ):
	TheSourceFilename = str(TheSourceFilename)
	TheTargetFilename = str(TheTargetFilename)
	print 'Comparing',TheSourceFilename,TheTargetFilename

	StorageFilename = os.path.join( os.getcwd(), str(StorageFilename) )
	LogFilename = os.path.join( os.getcwd(), str(LogFilename) )

	StorageDB = DiffEngine.DBWrapper( StorageFilename )

	ida_client_manager = DiffEngine.IDAClientManager()
	ida_client_manager.SetIDAPath( IDAPath );
	ida_client_manager.SetOutputFilename(StorageFilename);
	ida_client_manager.SetLogFilename(LogFilename);
	ida_client_manager.RunIDAToGenerateDB(TheSourceFilename,0L,0L);
	ida_client_manager.RunIDAToGenerateDB(TheTargetFilename,0L,0L);

	DiffMachine = DiffEngine.DiffMachine()
	DiffMachine.Retrieve(StorageDB)
	DiffMachine.Analyze()
	DiffMachine.Save(StorageDB)

if __name__ == '__main__':
	TheSourceFilename = sys.argv[1]
	TheTargetFilename = sys.argv[2]

	StorageFilename = 'test.dgf'
	LogFilename = 'test.log'

	IDAPath = r'C:\Program Files (x86)\IDA\idag.exe'
	DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath )
	
