import os
import popen2
import win32ver
import dircache
import shutil
import string

import PatchDatabaseWrapper

class MSFileProcessor:
	DebugLevel = 0
	NotInterestedFiles = [ 'spmsg.dll', 'spuninst.exe', 'spcustom.dll', 'update.exe', 'updspapi.dll', 'HotFixInstallerUI.dll' ]
	def __init__(self, source_binaries_folder, target_binaries_folder, database = None, databasename = 'test.db' ):
		self.TemporaryExtractedFilesFolderFolder = source_binaries_folder
		self.TargetBinariesFolder = target_binaries_folder

		self.DatabaseName = databasename
		if database:
			self.Database = database
		else:
			self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )
		self.Download = None

	def ExtractFilesInDatabase( self ):
		for download in self.Database.GetDownloads():
			self.ExtractDownload( download )

	def ExtractDownload( self, download , filename = None ):
		print 'ExtractDownload', download, filename
		if not filename:
			filename = download.filename
		if os.path.isfile( filename ) and filename[-4:]=='.exe':
			print 'Filename', filename
			if self.ExtractMSArchive( filename ):
				self.ScrapTemporaryExtractedFilesFolder( download )
				self.RemoveTemporaryFiles()

	def ExtractMSArchive( self, filename ):		
		popen2.popen2( filename + " /x:"+self.TemporaryExtractedFilesFolderFolder + " /quiet" )
		return True

	def ExtractFilesInDirectory( self, dirname ):
		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isfile( full_path ) and full_path[-4:]=='.exe':
				print full_path
				if self.ExtractFile( full_path ):
					self.ScrapTemporaryExtractedFilesFolder( self.Download )
					self.RemoveTemporaryFiles()

	def ExtractFile( self, filename ):
		#Filename
		print 'Filename', filename
		self.Download = self.Database.GetDownloadByFilename( filename )
		print 'Download', self.Download
		if self.Download:
			self.ExtractMSArchive( filename )
			return True
		return False

	def QueryFile( self, filename ):
		VersionInfo = {}
		info = win32ver.GetFileVersionInfo( filename )
		if info:
			lclist = win32ver.VerQueryValue( info )
			if lclist:
				if self.DebugLevel > 2:
					print 'lclist', lclist

				lclist = win32ver.VerQueryValue( info )
				block = u"\\StringFileInfo\\%04x%04x\\" % lclist[0]
				for s in ( "CompanyName", "FileVersion", "ProductVersion" ):
					value = win32ver.VerQueryValue( info, block+s)
					if not value:
						value = ""
					VersionInfo[s] = value
					if self.DebugLevel > 2:
						print "\t", s, value
		return VersionInfo

	def ScrapTemporaryExtractedFilesFolder( self, download, dirname = None ):
		if not dirname:
			dirname = self.TemporaryExtractedFilesFolderFolder

		if not os.path.isdir( dirname ):
			return 

		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isdir( full_path ):
				self.ScrapTemporaryExtractedFilesFolder( download, full_path )
			else:
				if self.DebugLevel > 2:
					print full_path
				version_info = self.QueryFile( full_path )
				filename = os.path.basename( full_path )
				
				if not filename in self.NotInterestedFiles:
					if len(version_info) > 0:
						if self.DebugLevel > 2:
							print version_info
						
						target_full_path = full_path
						if self.TemporaryExtractedFilesFolderFolder != self.TargetBinariesFolder:
							target_directory = os.path.join( self.TargetBinariesFolder, version_info['CompanyName'], filename , string.replace( version_info['FileVersion'], ':', '_' ) )
							target_full_path = os.path.join( target_directory, filename )

							if not os.path.isdir( target_directory ):
								os.makedirs( target_directory )
							print 'Copy to ',target_full_path
							shutil.copyfile( full_path, target_full_path )

						#TODO: Put to the Index Database
						operating_system = 'Windows XP'
						patch_identifier = ''
						service_pack = ''

						ret = self.Database.GetFileByFileInfo( filename, version_info['CompanyName'], version_info['FileVersion'] )
						if ret and len(ret)>0 and 0:
							print 'Already there:', full_path, version_info
						else:
							print 'New', download, full_path, version_info, 'filename=',filename
							self.Database.AddFile( 
								download,
								operating_system, 
								service_pack, 
								filename, 
								version_info['CompanyName'], 
								version_info['FileVersion'], 
								patch_identifier, 
								target_full_path
							)
		self.Database.Commit()

	def RemoveTemporaryFiles( self, dirname = None ):
		if self.TemporaryExtractedFilesFolderFolder != self.TargetBinariesFolder:
			if not dirname:
				dirname = self.TemporaryExtractedFilesFolderFolder
			if os.path.isdir( dirname ):
				shutil.rmtree( dirname )

		"""
		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isdir( full_path ):
				self.RemoveTemporaryFiles( full_path )
				#Remove directory
				os.remove( full_path )
			else:
				print full_path
				#Remove file
				os.remove( full_path )
		"""

import unittest, sys, os

# These strings are rather system dependant.
EXPECTEDSTRINGS = [
	("OriginalFilename", "REGEDIT.EXE"),
	("ProductVersion", "5.00.2134.1"),
	("FileVersion", "5.00.2134.1"),
	("FileDescription", "Registry Editor"),
	("Comments", None),
	("InternalName", "REGEDIT"),
	#("ProductName", "Microsoft(R) Windows (R) 2000 Operating System"),
	("CompanyName", "Microsoft Corporation"),
	("LegalCopyright", "Copyright (C) Microsoft Corp. 1981-1999"),
	("LegalTrademarks", None),
	#("PrivateBuild", None),
	("SpecialBuild", None)]

TESTFILE = os.path.join(os.environ['windir'], 'regedit.exe')

class Win32VerTest(unittest.TestCase):
	def setUp(self):
		self.info = win32ver.GetFileVersionInfo( TESTFILE )
		assert(self.info is not None)

	def tearDown(self):
		pass

	def testLCList(self):
		'''Retrive language codepair list'''
		# Calling VerQueryValue with no path should return a list
		# of language, codepage pairs.
		lclist = win32ver.VerQueryValue(self.info)
		print 'lclist', lclist
		self.assertEquals(lclist, [(1033, 1200)])

	def testValues(self):
		'''Retrieve version strings'''
		lclist = win32ver.VerQueryValue(self.info)
		block = u"\\StringFileInfo\\%04x%04x\\" % lclist[0]
		for s, expected in EXPECTEDSTRINGS:
			value = win32ver.VerQueryValue(self.info, block+s)
			print s, value
			#self.assertEquals(value, expected)

if __name__=='__main__':
	#unittest.main()
	TemporaryExtractedFilesFolderFolder = "Out"
	#TemporaryExtractedFilesFolderFolder = r"T:\mat\Projects\Binaries\Windows XP"
	TargetBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
	PatchBinary = r'Patches\WindowsXP-KB950762-x86-ENU.exe'

	file_store = MSFileProcessor( TemporaryExtractedFilesFolderFolder, TargetBinariesFolder )
	print file_store.ExtractFilesInDatabase()
	#file_store.ExtractFilesInDirectory( "Patches" )
	#if file_store.ExtractFile( PatchBinary ):
	#	file_store.ScrapTemporaryExtractedFilesFolder()
	#	file_store.RemoveTemporaryFiles()
