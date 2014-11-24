import sys
import DiffEngine
import os
import hashlib
import subprocess

LogToStdout = 0x1
LogToDbgview = 0x2
LogToFile = 0x4
LogToIDAMessageBox = 0x8

class DarunGrim:
	def __init__ ( self, src_filename='', target_filename='', start_ida_listener=True ):
		self.SetSourceFilename(src_filename)
		self.SetTargetFilename(target_filename)

		self.DarunGrim = DiffEngine.DarunGrim()
	
		self.IDAPath=r'C:\Program Files (x86)\IDA 6.6\idaq.exe' 
		self.DarunGrim.SetIDAPath(self.IDAPath) #TODO:
		self.DarunGrim.SetLogParameters(LogToStdout, 10, "")

		if start_ida_listener:
			self.DarunGrim.StartIDAListenerThread()
		self.DGFSotrage=''

	def SetSourceController(self,identity):
		self.DarunGrim.SetSourceController(str(identity))

	def SetTargetController(self,identity):
		self.DarunGrim.SetTargetController(str(identity))

	def SetSourceFilename(self,src_filename):
		self.SrcFilename = str(src_filename)
		
		if self.SrcFilename:
			self.DarunGrim.SetSourceFilename( self.SrcFilename )

	def SetTargetFilename(self,target_filename):
		self.TargetFilename = str(target_filename)

		if self.TargetFilename:
			self.DarunGrim.SetTargetFilename( self.TargetFilename )

	def SetLogFile(self,log_filename,log_level=10):
		self.DarunGrim.SetLogParameters(LogToFile, log_level, str(log_filename))

	def SetIDAPath( self, ida_path ):
		self.DarunGrim.SetIDAPath( ida_path )

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

	def PerformDiff( self, output_storage, src_ida_log_filename = "src.log", target_ida_log_filename = "target.log" ):
		src_storage=self.GetDGFName(self.SrcFilename)
		target_storage=self.GetDGFName(self.TargetFilename)
		output_storage=str(output_storage)

		src_ida_log_filename=os.path.join( os.getcwd(), src_ida_log_filename)
		target_ida_log_filename=os.path.join( os.getcwd(), target_ida_log_filename)

		if not os.path.isfile(src_storage):
			self.DarunGrim.GenerateSourceDGFFromIDA(src_storage, src_ida_log_filename)

		if not os.path.isfile(target_storage):
			self.DarunGrim.GenerateTargetDGFFromIDA(target_storage, target_ida_log_filename)

		self.DarunGrim.PerformDiff(src_storage, 0, target_storage, 0, output_storage);

	def OpenIDA(self,filename):
		subprocess.Popen([self.IDAPath,  filename])

	def SyncIDA( self ):
		self.DarunGrim.AcceptIDAClientsFromSocket()
		
	def JumpToAddresses( self, source_address, target_address ):
		self.DarunGrim.JumpToAddresses( source_address, target_address )

	def ColorAddress( self, type, start_address, end_address, color ):
		self.DarunGrim.ColorAddress( type, start_address, end_address, color )

if __name__ == '__main__':
	from optparse import OptionParser

	parser = OptionParser()
	parser.add_option("-s", "--source_address", dest="source_address",
						help="Source function address", type="int", default=0, metavar="SOURCE_ADDRESS")

	parser.add_option("-t", "--target_address", dest="target_address",
						help="Target function address", type="int", default=0, metavar="TARGET_ADDRESS")

	(options, args) = parser.parse_args()

	src_storage = args[0]
	target_storage = args[1]
	result_storage = args[2]
	
	#options.source_address, options.target_address
	darungrim=DarunGrim(src_storage, target_storage)
	darungrim.SetDGFSotrage(os.getcwd())
	darungrim.PerformDiff("out.dgf")
