import sys
import DiffEngine

TheSourceFilename = sys.argv[1]
TheTargetFilename = sys.argv[2]

StorageFilename = "test.db" 
LogFilename = "test.log"
IDAPath = r'C:\Program Files (x86)\IDA\idag.exe'

print 'Comparing',TheSourceFilename,TheTargetFilename

StorageDB = DiffEngine.DBWrapper( StorageFilename )

ida_client_manager = DiffEngine.IDAClientManager()
ida_client_manager.SetIDAPath( IDAPath );
ida_client_manager.SetOutputFilename(StorageFilename);
ida_client_manager.SetLogFilename(LogFilename);
ida_client_manager.RunIDAToGenerateDB(TheSourceFilename,0L,0L);
ida_client_manager.RunIDAToGenerateDB(TheTargetFilename,0L,0L);

DiffMachine = DiffEngine.DiffMachine()
DiffMachine.Retrieve(StorageDB,TRUE,1,2);

DiffMachine.Analyze()
DiffMachine.Save(StorageDB);
