import os
import popen2
import win32ver
import dircache
import shutil
import string

import Indexer

class FileStore:
	DebugLevel = 0
	def __init__(self, source_binaries_folder, target_binaries_folder, indexer_database_name = 'index.db' ):
		self.SourceBinariesFolder = source_binaries_folder
		self.TargetBinariesFolder = target_binaries_folder
		self.IndexerDatabaseName = indexer_database_name
		self.IndexerDatabase = Indexer.Database( self.IndexerDatabaseName )

	def ExtractFile( self, Filename ):
		popen2.popen2( Filename + " /x:"+self.SourceBinariesFolder + " /quiet" )
		
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

		for file in dircache.listdir( dirname ):
			full_path = os.path.join( dirname, file )
			if os.path.isdir( full_path ):
				self.ScapSourceBinaries( full_path )
			else:
				if self.DebugLevel > 2:
					print full_path
				version_info = self.QueryFile( full_path )
				filename = os.path.basename( full_path )
				
				if len(version_info) > 0:
					if self.DebugLevel > 2:
						print version_info
					
					if self.SourceBinariesFolder != self.TargetBinariesFolder:
						target_directory = os.path.join( self.TargetBinariesFolder, version_info['CompanyName'], filename , string.replace( version_info['FileVersion'], ':', '_' ) )
						target_full_path = os.path.join( target_directory, filename )

						if not os.path.isdir( target_directory ):
							os.makedirs( target_directory )
						print 'Copy to ',target_full_path
						shutil.copyfile( full_path, target_full_path )
					#TODO: Put to the Index Database
					print full_path, version_info
					operating_system = 'Windows XP'
					patch_identifier = ''
					service_pack = ''

					self.IndexerDatabase.Add( 
						operating_system, 
						service_pack, 
						filename, 
						version_info['CompanyName'], 
						version_info['FileVersion'], 
						patch_identifier, 
						full_path
					)

	def RemoveOutput( self, dirname = None ):
		if self.SourceBinariesFolder != self.TargetBinariesFolder:
			if not dirname:
				dirname = self.SourceBinariesFolder
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
	
	SourceBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
	TargetBinariesFolder = r"T:\mat\Projects\Binaries\Windows XP"
	PatchBinary = r'Patches\WindowsXP-KB950762-x86-ENU.exe'

	file_store = FileStore( SourceBinariesFolder, TargetBinariesFolder )
	#file_store.ExtractFile( PatchBinary )
	file_store.ScapSourceBinaries()
	#file_store.RemoveOutput()
