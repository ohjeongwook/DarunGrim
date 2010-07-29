import os
import popen2
import win32ver
import dircache
import shutil
import string

import PatchDatabaseWrapper

class FileProcessor:
	DebugLevel = 0
	NotInterestedFiles = [ 'spmsg.dll', 'spuninst.exe', 'spcustom.dll', 'update.exe', 'updspapi.dll', 'HotFixInstallerUI.dll' ]
	Database = None

	def __init__( self, databasename = None, database = None ):
		print 'FileProcessor', databasename, database
		self.DatabaseName = databasename
		if database:
			self.Database = database
		else:
			self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )
		print 'Database', self.Database

	def IndexFilesInFoler( self, src_dirname, target_dirname = None, download = None, copy_file = True ):
		if not os.path.isdir( src_dirname ):
			return 

		for file in dircache.listdir( src_dirname ):
			current_path = os.path.join( src_dirname, file )
			if os.path.isdir( current_path ):
				try:
					self.IndexFilesInFoler( os.path.join( src_dirname, file ), target_dirname, download )
				except:
					pass
			else:
				#TODO: Check MZ at the start of the file
				if self.DebugLevel > 2:
					print current_path
				version_info = self.QueryFile( current_path )
				filename = os.path.basename( current_path )
				
				if not filename in self.NotInterestedFiles:
					if len(version_info) > 0 and version_info.has_key( 'CompanyName' ) and  version_info.has_key( 'FileVersion' ):
						if self.DebugLevel > 2:
							print version_info
						
						try:
							if target_dirname:
								target_relative_directory = os.path.join( version_info['CompanyName'], filename , string.replace( version_info['FileVersion'], ':', '_' ) )
								target_relative_filename = os.path.join( target_relative_directory, os.path.basename( current_path ) )
								
								target_full_directory = os.path.join( target_dirname, target_relative_directory )
								target_full_filename = os.path.join( target_dirname, target_relative_filename )

								print 'target_relative_directory', target_relative_directory
								print 'target_relative_filename', target_relative_filename
								print 'target_full_filename',target_full_filename

								if not os.path.isdir( target_full_directory ):
									os.makedirs( target_full_directory )

								if current_path != target_full_filename:
									if copy_file:
										print 'Copy to',target_full_filename
										shutil.copyfile( current_path, target_full_filename )
									else:
										print 'Move to',target_full_filename
										shutil.move( current_path, target_full_filename )
							else:
								target_relative_filename = current_path

							#TODO: Put to the Index Database
							operating_system = 'Windows XP'
							patch_identifier = ''
							service_pack = ''

							ret = self.Database.GetFileByFileInfo( filename, version_info['CompanyName'], version_info['FileVersion'] )
							if ret and len(ret)>0:
								print 'Already there:', current_path, version_info
								self.Database.UpdateFile( 
									download,
									operating_system, 
									service_pack, 
									filename, 
									version_info['CompanyName'], 
									version_info['FileVersion'], 
									patch_identifier, 
									target_relative_filename
								)
								
							else:
								print 'New', download, current_path, version_info, 'filename=',filename
								self.Database.AddFile( 
									download,
									operating_system, 
									service_pack, 
									filename, 
									version_info['CompanyName'], 
									version_info['FileVersion'], 
									patch_identifier, 
									target_relative_filename
								)
						except:
							pass
		self.Database.Commit()

	def QueryFile( self, filename ):
		VersionInfo = {}
		info = win32ver.GetFileVersionInfo( filename )
		if info:
			lclists = []
			lclists.append( win32ver.VerQueryValue( info ) )
			lclists.append( [(1033,0x04E4)] )

			for lclist in lclists:
				if self.DebugLevel > 2:
					print 'lclist', lclist
				block = u"\\StringFileInfo\\%04x%04x\\" % lclist[0]
				for s in ( "CompanyName", "Company", "FileVersion", "File Version", "ProductVersion" ):
					value = win32ver.VerQueryValue( info, block+s)
					if self.DebugLevel > 2:
						print "\t", s,'=',value
					if value and not VersionInfo.has_key( s ):
						VersionInfo[s] = value
		return VersionInfo

class MSFileProcessor( FileProcessor ):
	DebugLevel = 0
	def __init__(self, source_binaries_folder, target_binaries_folder, database = None, databasename = 'test.db' ):
		self.TemporaryExtractedFilesFolderFolder = source_binaries_folder
		self.TargetBinariesFolder = target_binaries_folder

		self.file_processor = FileProcessor( databasename = databasename, database = database )
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
				self.file_processor.IndexFilesInFoler( self.TemporaryExtractedFilesFolderFolder, self.TargetBinariesFolder, download )
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
					self.IndexFilesInFoler( self.TemporaryExtractedFilesFolderFolder, self.TargetBinariesFolder, self.Download )
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

	test = 2
	if test == 1:
		TemporaryExtractedFilesFolderFolder = "Out"
		#TemporaryExtractedFilesFolderFolder = r"T:\mat\Projects\Binaries\Windows XP"
		TargetBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
		PatchBinary = r'Patches\WindowsXP-KB950762-x86-ENU.exe'
	
		file_store = MSFileProcessor( TemporaryExtractedFilesFolderFolder, TargetBinariesFolder, databasename = 'ms.db' )
		print file_store.ExtractFilesInDatabase()
		#file_store.ExtractFilesInDirectory( "Patches" )
		#if file_store.ExtractFile( PatchBinary ):
		#	file_store.IndexFilesInFoler()
		#	file_store.RemoveTemporaryFiles()
	elif test == 2:
		file_store = FileProcessor( databasename = r'..\UI\Web\index.db' )
		#file_store.IndexFilesInFoler( r'T:\mat\Projects\Binaries' )
		#file_store.IndexFilesInFoler( r'C:\Program Files (x86)\Adobe', target_dirname = r'T:\mat\Projects\Binaries\AdobePatch' )
		file_store.IndexFilesInFoler( r'T:\mat\Projects\Binaries\AdobePatch' )
		file_store.IndexFilesInFoler( r'T:\mat\Projects\Binaries\Adobe' )
