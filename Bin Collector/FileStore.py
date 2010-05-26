import os
import popen2
import win32ver
import dircache
import shutil
import string

import PatchesDatabaseWrapper

class FileStore:
	DebugLevel = 0
	NotInterestedFiles = [ 'spmsg.dll', 'spuninst.exe', 'spcustom.dll', 'update.exe', 'updspapi.dll' ]
	def __init__(self, source_binaries_folder, target_binaries_folder, PatchesDatabaseWrapper_database_name = 'test.db' ):
		self.SourceBinariesFolder = source_binaries_folder
		self.TargetBinariesFolder = target_binaries_folder
		self.DatabaseName = PatchesDatabaseWrapper_database_name
		self.Database = PatchesDatabaseWrapper.Database( self.DatabaseName )
		self.Download = None

	def ExtractFilesInDatabase( self ):
		for download in self.Database.GetDownloads():
			full_path = download.filename
			if os.path.isfile( full_path ) and full_path[-4:]=='.exe':
				print full_path
				if self.ExtractFile( full_path ):
					self.ScapSourceBinaries()
					self.RemoveOutput()

	def ExtractFilesInDirectory( self, dirname ):
		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isfile( full_path ) and full_path[-4:]=='.exe':
				print full_path
				if self.ExtractFile( full_path ):
					self.ScapSourceBinaries()
					self.RemoveOutput()

	def ExtractFile( self, Filename ):
		#Filename
		self.Download = self.Database.GetDownloadByFilename( Filename )
		if self.Download:
			popen2.popen2( Filename + " /x:"+self.SourceBinariesFolder + " /quiet" )
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

	def ScapSourceBinaries( self, dirname = None ):
		if not dirname:
			dirname = self.SourceBinariesFolder

		if not os.path.isdir( dirname ):
			return 

		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isdir( full_path ):
				self.ScapSourceBinaries( full_path )
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
						if self.SourceBinariesFolder != self.TargetBinariesFolder:
							target_directory = os.path.join( self.TargetBinariesFolder, version_info['CompanyName'], filename , string.replace( version_info['FileVersion'], ':', '_' ) )
							target_full_path = os.path.join( target_directory, filename )

							if not os.path.isdir( target_directory ):
								os.makedirs( target_directory )
							#print 'Copy to ',target_full_path
							shutil.copyfile( full_path, target_full_path )

						#TODO: Put to the Index Database
						operating_system = 'Windows XP'
						patch_identifier = ''
						service_pack = ''

						ret = self.Database.GetFileByFileInfo( filename, version_info['CompanyName'], version_info['FileVersion'] )
						if ret and len(ret)>0:
							print 'Already there:', full_path, version_info
						else:
							print 'New', full_path, version_info
							self.Database.AddFile( 
								self.Download,
								operating_system, 
								service_pack, 
								filename, 
								version_info['CompanyName'], 
								version_info['FileVersion'], 
								patch_identifier, 
								target_full_path
							)
		self.Database.Commit()

	def RemoveOutput( self, dirname = None ):
		if self.SourceBinariesFolder != self.TargetBinariesFolder:
			if not dirname:
				dirname = self.SourceBinariesFolder
			if os.path.isdir( dirname ):
				shutil.rmtree( dirname )

		"""
		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isdir( full_path ):
				self.RemoveOutput( full_path )
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
	SourceBinariesFolder = "Out"
	#SourceBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
	TargetBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
	PatchBinary = r'Patches\WindowsXP-KB950762-x86-ENU.exe'

	file_store = FileStore( SourceBinariesFolder, TargetBinariesFolder )
	print file_store.ExtractFilesInDatabase()
	#file_store.ExtractFilesInDirectory( "Patches" )
	#if file_store.ExtractFile( PatchBinary ):
	#	file_store.ScapSourceBinaries()
	#	file_store.RemoveOutput()
