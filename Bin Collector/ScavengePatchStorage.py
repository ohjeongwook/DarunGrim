from FileStore import *

TargetBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
SourceBinariesFolder = TargetBinariesFolder

file_store = FileStore( SourceBinariesFolder, TargetBinariesFolder )
file_store.ScapSourceBinaries()
