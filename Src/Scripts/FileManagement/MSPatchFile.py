import os
import popen2
import win32ver
import dircache
import shutil
import string
import time
import datetime
import hashlib

class MSPatchHandler:
	DebugLevel = 0
	def __init__(self):
		self.TmpDirs=[]

	def GetFileTmpDir(self,filename):
		dir_name=os.path.dirname(filename)
		return os.path.join(dir_name,os.path.basename(filename)+".dir")

	def ExtractEXEArchive( self, filename ):
		tmp_dir=self.GetFileTmpDir(filename)
		popen2.popen2( filename + " /x:"+ tmp_dir + " /quiet" )
		self.TmpDirs.append(tmp_dir)
		return tmp_dir

	def RunExpandMSU(self,filename):
		tmp_dir=self.GetFileTmpDir(filename)
		cmdline="expand -f:* %s %s" % (filename, tmp_dir)

		try:
			os.makedirs(tmp_dir)
		except:
			pass

		popen2.popen2(cmdline)
		self.TmpDirs.append(tmp_dir)
		return tmp_dir

	def ExtractMSU(self,filename):
		print 'ExtractMSU:', filename
		tmp_dir=self.RunExpandMSU(filename)

		extracted_folders=[]
		for filename in dircache.listdir(tmp_dir):
			if filename[-4:].lower()=='.cab':
				cab_filename=os.path.join(tmp_dir,filename)

				extracted_folders.append(self.RunExpandMSU(cab_filename))

		return extracted_folders

	def Extract( self, filename ):
		if os.path.isfile( filename ):
			if filename[-4:].lower()=='.exe':
				extracted_folders=[]
				extracted_folders.append(self.ExtractEXEArchive(filename))

			elif filename[-4:].lower()=='.msu':
				extracted_folders=self.ExtractMSU(filename)

		return extracted_folders

	def CleanUpTmpDirs(self):
		for dir in self.TmpDirs:
			shutil.rmtree(dir)

if __name__=='__main__':
	from optparse import OptionParser
	import sys

	parser=OptionParser()

	parser.add_option('-e','--extract',
					dest='extract',help="Extract MS patch files", 
					action="store_true", default=False, 
					metavar="EXTRACT")

	parser.add_option('-s','--store',
					dest='store',help="Store MS patch files", 
					action="store_true", default=False, 
					metavar="STORE")

	parser.add_option('-t','--tags',
					dest='tags',help="Set tags files", 
					default="", 
					metavar="TAGS")

	(options,args)=parser.parse_args()

	if options.extract:
		filename=args[0]
		ms_patch_handler=MSPatchHandler()
		print ms_patch_handler.Extract(filename)

	elif options.store:
		import FileStore
		file_store = FileStore.FileProcessor( databasename = r'index.db' )

		filename=args[0]
		src_dirname = args[1]
		target_dirname = args[2]
		tags=options.tags.split(',')

		ms_patch_handler=MSPatchHandler()
		for dir in ms_patch_handler.Extract(filename):
			print 'Store: %s -> %s (tags:%s)' % (src_dirname, target_dirname, ','.join(tags))
			file_store.CheckInFiles( src_dirname, target_dirname, tags=tags )
