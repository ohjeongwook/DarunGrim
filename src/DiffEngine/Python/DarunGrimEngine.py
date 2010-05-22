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
	darun_grim.GenerateDB( 
		StorageFilename, LogFilename, 
		TheSourceFilename, 0L, 0L,
		TheTargetFilename, 0L, 0L)
	darun_grim.Analyze()

if __name__ == '__main__':
	TheSourceFilename = sys.argv[1]
	TheTargetFilename = sys.argv[2]

	StorageFilename = 'test.dgf'
	LogFilename = 'test.log'

	IDAPath = r'C:\Program Files (x86)\IDA\idag.exe'
	DiffFile( TheSourceFilename, TheTargetFilename, StorageFilename, LogFilename, IDAPath )
	
