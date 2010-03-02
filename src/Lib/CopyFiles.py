import os.path
import shutil

DIFF_ENGINE_DIR=r'..\DiffEngine'
SNIPPET_DIR=r'\mat\Projects\ResearchTools\DevEnv\Library\Snippets'
IPC_DIR=r'\mat\Projects\ResearchTools\DevEnv\Library\IPC'
CRYPTO_DIR=r'\mat\Projects\ResearchTools\DevEnv\Library\Crypto'
FILE_DIR=r'\mat\Projects\ResearchTools\DevEnv\Library\File'
DATABASE_DIR=r'\mat\Projects\ResearchTools\DevEnv\Library\Database'
SOCKET_LIB_DIR=r'\mat\Projects\ResearchTools\DevEnv\Library\Socket'
IDA_LIBRARY_DIR=r'\mat\Projects\ResearchTools\Binary\Static Analysis\IDALib'

filenames=[]

filenames.append(r'T:\mat\Projects\ResearchTools\Binary\Static Analysis\IDAVerifier\IDAVerifier.cpp')
filenames.append(r'T:\mat\Projects\ResearchTools\Binary\Static Analysis\IDAVerifier\IDAVerifier.h')
filenames.append(IPC_DIR+r'\TLV.h')
filenames.append(IPC_DIR+r'\SharedMemory.h')
filenames.append(IPC_DIR+r'\SharedMemory.cpp')
filenames.append(IPC_DIR+r'\SharedSocket.h')
filenames.append(IPC_DIR+r'\SharedSocket.cpp')
filenames.append(CRYPTO_DIR+r'\md5.h')
filenames.append(CRYPTO_DIR+r'\md5.cpp')
filenames.append(FILE_DIR+r'\fileinfo.h')
filenames.append(FILE_DIR+r'\fileinfo.cpp')
filenames.append(IDA_LIBRARY_DIR+r'\IdaIncludes.h')
filenames.append(IDA_LIBRARY_DIR+r'\IDAAnalysisCommon.h')
filenames.append(IDA_LIBRARY_DIR+r'\IDAAnalysis.h')
filenames.append(IDA_LIBRARY_DIR+r'\IDAAnalysis.cpp')
filenames.append(SOCKET_LIB_DIR+r'\SocketOperation.h')
filenames.append(SOCKET_LIB_DIR+r'\SocketOperation.cpp')
filenames.append(SNIPPET_DIR+r'\ProcessUtils.h')
filenames.append(SNIPPET_DIR+r'\ProcessUtils.cpp')

for file_name in filenames:
	if os.path.isfile(file_name):
		file_mtime=os.path.getmtime(file_name)
	else:
		file_mtime=0

	copied_file_name=os.path.basename(file_name)
	if os.path.isfile(copied_file_name):
		copied_file_mtime=os.path.getmtime(copied_file_name)
	else:
		copied_file_mtime=0
	
	if copied_file_mtime<file_mtime:
		print copied_file_name
		shutil.copyfile(file_name,copied_file_name)
	

