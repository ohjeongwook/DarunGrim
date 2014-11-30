import sys
import DiffEngine
import os
import hashlib
import subprocess
import dircache
import shutil
from _winreg import *
import tempfile
import win32api
import win32security
import win32con

LogToStdout = 0x1
LogToDbgview = 0x2
LogToFile = 0x4
LogToIDAMessageBox = 0x8

LOG_DARUNGRIM=0x00000001
LOG_DIFF_MACHINE=0x00000002
LOG_IDA_CONTROLLER=0x00000004
LOG_SQL=0x00000008
LOG_ONE_LOCATION_INFO=0x0000000F
LOG_MATCH_RATE=0x00000010


class DarunGrim:
	DebugLevel=0
	def __init__ ( self, src_filename='', target_filename='', ida_path='', start_ida_listener=False):
		self.SrcStorage=''
		self.TargetStorage=''
		self.IDAPath=''
		self.DarunGrim = DiffEngine.DarunGrim()
		self.DarunGrim.SetLogParameters(LogToStdout, 10, "")

		self.DarunGrim.AddSrcDumpAddress(0)
		self.DarunGrim.AddTargetDumpAddress(0)
		self.DarunGrim.EnableLogType(LOG_DIFF_MACHINE)

		if src_filename:
			self.SetSourceFilename(src_filename)

		if target_filename:
			self.SetTargetFilename(target_filename)

		self.SetIDAPath()
		self.ListeningPort=0

		if start_ida_listener:
			self.ListeningPort=self.DarunGrim.StartIDAListenerThread(self.ListeningPort)
		self.DGFSotrage=''

	def SetIDAPath(self,ida_path='',is_64=False):
		if ida_path=='' or not os.path.isfile(ida_path):
			if self.DebugLevel>0:
				print 'Locating IDA executables...'

			ida_executables=self.LocateIDAExecutables()
			if len(ida_executables)>0:
				ida_path=ida_executables[0][0]

				if self.DebugLevel>0:
					print 'Using IDA executable [%s] ...' % ida_path

		if ida_path:
			ida_path=str(ida_path)
			if is_64:
				self.IDA64Path=ida_path
			else:
				self.IDAPath=ida_path
			
			self.DarunGrim.SetIDAPath(ida_path,is_64)
		else:
			if self.DebugLevel>0:
				print 'No IDA found'

	def CheckIDAPlugin(self):
		darungrim_plugin_path=os.path.join(os.path.dirname(self.IDAPath),"plugins/DarunGrimPlugin.plw")
		if os.path.isfile(darungrim_plugin_path):
			return True
		return False

	def InstallIDAPlugin(self,filename):
		if not self.IDAPath:
			return (False, 'Invalid IDA path')

		darungrim_plugin_path=os.path.join(os.path.dirname(self.IDAPath),"plugins\\DarunGrimPlugin.plw")

		ph = win32api.GetCurrentProcess()
		th = win32security.OpenProcessToken(ph,win32con.MAXIMUM_ALLOWED)

		virtual_store_enabled=win32security.GetTokenInformation(th, win32security.TokenVirtualizationEnabled)
		if virtual_store_enabled:
			return (False,'Program files are under Virtual Store.')

		try:
 			shutil.copy(filename, darungrim_plugin_path)
		except Exception as e:
			s = str(e)
			return (False, s)

		if not os.path.isfile(darungrim_plugin_path):
			return (False,'Not copied')

		return (True,"File location: %s" % darungrim_plugin_path)

	def LocateIDAExecutables(self,is_64=False):
		if is_64:
			executables=['idaq64.exe','idag64.exe']
		else:
			executables=['idaq.exe','idag.exe']

		ida_executables=[]
		for (ida_path,ctime) in self.LocateIDAInstallations():
			for executable in executables:
				filename=os.path.join(ida_path,executable)
				if os.path.isfile(filename):
					ida_executables.append([filename, os.path.getctime(filename)])

		ida_executables=sorted(ida_executables, key=lambda x:x[1], reverse=True)

		return ida_executables

	def LocateIDAInstallations(self):
		ida_paths={}
		programs_files={}
		programs_files[os.environ['ProgramFiles(x86)']]=1
		programs_files[os.environ['ProgramFiles']]=1

		for programs_file in programs_files.keys():
			for dir in dircache.listdir(programs_file):
				if dir[0:4]=='IDA ':
					ida_paths[os.path.join(programs_file,dir)]=1

		reg=ConnectRegistry(None,HKEY_LOCAL_MACHINE)
		key=OpenKey(reg,r"SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall")

		i=0
		while True:
			try:
				subkey=EnumKey(key,i)
				if subkey[0:4]=='IDA ':
					ida_key=OpenKey(key,subkey)
					(value,type)=QueryValueEx(ida_key,"Inno Setup: App Path")
					ida_paths[value]=1
				i+=1
			except:
				break
		"""
		TODO:
			HKEY_CLASSES_ROOT\Applications\idaq.exe\shell\open\command
			HKEY_CLASSES_ROOT\IDApro.Database32\shell\open\command
			HKEY_CLASSES_ROOT\IDApro.Database64\shell\open\command
			HKEY_CLASSES_ROOT\Local Settings\Software\Microsoft\Windows\Shell\MuiCache
			HKEY_CURRENT_USER\Software\Hex-Rays\IDA
			HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.i64\OpenWithList
			HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\.idb\OpenWithList
			HKEY_CURRENT_USER\Software\Hex-Rays
		"""

		folders=[]
		for folder in ida_paths.keys():
			folders.append([folder, os.path.getctime(folder)])

		folders=sorted(folders, key=lambda x:x[1], reverse=True)

		return folders

	def InstallIDAPlugins(self,plugin_filename):
		for [ida_path, plugin_path] in self.CheckIDAPlugins():
			if self.DebugLevel>0:
				print "Installing DarunGrim Plugin %s -> %s" % (plugin_filename, plugin_path)
			shutil.copy(plugin_filename, plugin_path)

	def CheckIDAPlugins(self):
		missing_plugins=[]
		for (ida_path,ctime) in self.LocateIDAInstallations():
			plugin_path=os.path.join(os.path.join(ida_path,"plugins"),"DarunGrimPlugin.plw")
			if not os.path.isfile(plugin_path):
				if self.DebugLevel>0:
					print 'DarunGrim Plugin missing: ', plugin_path
				missing_plugins.append([ida_path, plugin_path])

		return missing_plugins

	def SetSourceController(self,identity):
		self.DarunGrim.SetSourceController(str(identity))

	def SetTargetController(self,identity):
		self.DarunGrim.SetTargetController(str(identity))

	def SetSourceFilename(self,src_filename, is_dgf=False):
		self.SrcFilename = str(src_filename)
		
		if self.SrcFilename:
			self.DarunGrim.SetSourceFilename( self.SrcFilename )

	def SetTargetFilename(self,target_filename, is_dgf=False):
		self.TargetFilename = str(target_filename)

		if self.TargetFilename:
			self.DarunGrim.SetTargetFilename( self.TargetFilename )

	def SetLogFile(self,log_filename,log_level=10):
		self.DarunGrim.SetLogParameters(LogToFile, log_level, str(log_filename))

	def SetDGFSotrage(self,dgf_dir):
		self.DGFSotrage=dgf_dir

	def GetDGFName(self,filename):
		if self.DGFSotrage:
			fd=open(filename,'rb')
			data=fd.read()
			fd.close()

			s=hashlib.sha1()
			s.update(data)

			filename=os.path.join(self.DGFSotrage,"%s.dgf" % s.hexdigest())
		else:
			if filename[-4]=='.':
				filename=filename[0:-4] + ".dgf"
			else:
				filename=filename + '.dgf'

		return filename

	def Is64(self,filename):
		import pefile
		pe = pefile.PE(filename)
		_32bitFlag = pefile.IMAGE_CHARACTERISTICS['IMAGE_FILE_32BIT_MACHINE']

		if ( pe.FILE_HEADER.Machine & _32bitFlag ) == _32bitFlag:
			return False
		else:
			return True

	def SetStorageNames(self, src_storage, target_storage):
		self.SrcStorage=str(src_storage)
		self.TargetStorage=str(target_storage)

	def PerformDiff( self, output_storage, src_ida_log_filename = "src.log", target_ida_log_filename = "target.log" ):
		if not self.SrcStorage:
			self.SrcStorage=self.GetDGFName(self.SrcFilename)
			src_ida_log_filename=os.path.join( os.getcwd(), str(src_ida_log_filename))

			if not os.path.isfile(self.SrcStorage) or os.path.getsize(self.SrcStorage)==0:
				if self.Is64(self.SrcFilename):
					src_is_64=True
				else:
					src_is_64=False

				print 'Generate DarunGrim data file %s -> %s' % (self.SrcFilename, self.SrcStorage)
				self.DarunGrim.GenerateSourceDGFFromIDA(str(self.SrcStorage), str(src_ida_log_filename), src_is_64)

		if not self.TargetStorage:
			self.TargetStorage=self.GetDGFName(self.TargetFilename)

			output_storage=str(output_storage)

			target_ida_log_filename=os.path.join( os.getcwd(), str(target_ida_log_filename))


			if not os.path.isfile(self.TargetStorage) or os.path.getsize(self.TargetStorage)==0:
				if self.Is64(self.TargetFilename):
					target_is_64=True
				else:
					target_is_64=False

				print 'Generate DarunGrim data file %s -> %s' % (self.TargetFilename, self.TargetStorage)
				self.DarunGrim.GenerateTargetDGFFromIDA(str(self.TargetStorage), str(target_ida_log_filename), target_is_64)

		print 'Perform Diffing...'
		self.DarunGrim.PerformDiff(str(self.SrcStorage), 0, str(self.TargetStorage), 0, str(output_storage))

	def OpenIDA(self,filename):
		if filename[-4:].lower()=='.idb':
			is_64=False
		elif filename[-4:].lower()=='.i64':
			is_64=True
		else:
			if self.Is64(filename):
				is_64=True
			else:
				is_64=False

		if is_64:
			ida_path=self.IDA64Path
		else:
			ida_path=self.IDAPath

		fd=tempfile.TemporaryFile(delete=False)

		idc_data="static main()\n" + \
				"{\n" + \
				"	Wait();\n" + \
				"	RunPlugin( \"DarunGrimPlugin\", 1 );\n" + \
				"	ConnectToDarunGrim(%d);\n" + \
				"}"
		
		fd.write(idc_data % self.ListeningPort)
		idc_filename=fd.name
		fd.close()

		subprocess.Popen([ida_path, "-S" + idc_filename, filename])
		
	def SyncIDA( self ):
		self.DarunGrim.AcceptIDAClientsFromSocket()
		
	def JumpToAddresses( self, source_address, target_address ):
		self.DarunGrim.JumpToAddresses( source_address, target_address )

	def ColorAddress( self, type, start_address, end_address, color ):
		self.DarunGrim.ColorAddress( type, start_address, end_address, color )

if __name__ == '__main__':
	from optparse import OptionParser
	import pprint

	parser = OptionParser()

	parser.add_option('-d','--diff',
					dest='diff',help="Perform diff", 
					action="store_true", default=False, 
					metavar="DIFF")

	parser.add_option('-i','--ida',
					dest='ida',help="Locate IDA", 
					action="store_true", default=False, 
					metavar="IDA")

	parser.add_option("-s", "--source_address", dest="source_address",
						help="Source function address", type="int", default=0, metavar="SOURCE_ADDRESS")

	parser.add_option("-t", "--target_address", dest="target_address",
						help="Target function address", type="int", default=0, metavar="TARGET_ADDRESS")

	(options, args) = parser.parse_args()

	if options.diff:
		src_storage = args[0]
		target_storage = args[1]
		result_storage = args[2]
	
		darungrim=DarunGrim(src_storage, target_storage)
		darungrim.SetDGFSotrage(os.getcwd())
		darungrim.PerformDiff("out.dgf")

	elif options.ida:
		darungrim=DarunGrim()
		pprint.pprint(darungrim.LocateIDAInstallations())
		darungrim.InstallIDAPlugin(r'C:\mat\Src\DarunGrim\Release\DarunGrimPlugin.plw')
		ida_executables=darungrim.LocateIDAExecutables()

		pprint.pprint(ida_executables)
