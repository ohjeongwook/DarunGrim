from FileStore import *

SourceBinariesFolder = "TmpOut"
TargetBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"

file_store = FileStore( SourceBinariesFolder, TargetBinariesFolder )
file_store.ExtractFilesInDatabase()
