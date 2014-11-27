from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *
import DarunGrimDatabase
import DiffEngine
from Graphs import *
import FlowGrapher
import FileStoreBrowser
import FileStoreDatabase
import DarunGrimEngine

import pprint
import multiprocessing.forking
import multiprocessing
from multiprocessing import Process
import time
import os
import operator
import subprocess

class FunctionMatchTable(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.match_list=[]

		if database_name:
			database = DarunGrimDatabase.Database(database_name)

			for function_match_info in database.GetFunctionMatchInfo():
				if function_match_info.match_rate < 100:
					if self.Debug>0:
						print "%s\t%s\t%s\t%s\t%s%%\t%d\t%d\t%d\t%d\t%d\t%d" % (function_match_info.source_function_name,
																function_match_info.target_function_name,
																str(function_match_info.block_type),
																str(function_match_info.type),
																str( function_match_info.match_rate ),
																function_match_info.match_count_for_the_source, 
																function_match_info.non_match_count_for_the_source, 
																function_match_info.match_count_with_modificationfor_the_source, 
																function_match_info.match_count_for_the_target, 
																function_match_info.non_match_count_for_the_target, 
																function_match_info.match_count_with_modification_for_the_target)

					self.match_list.append([function_match_info.source_function_name,
										function_match_info.target_function_name,
										"%d%%" % (function_match_info.match_rate),
										function_match_info])

	def GetFunctionAddresses(self,index):
		return [self.match_list[index][3].source_address, self.match_list[index][3].target_address]

	def rowCount(self,parent):
		return len(self.match_list)
	
	def columnCount(self,parent):
		return 3

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.match_list[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Orig", "Patched", "Match"][col]
		return None

	def sort(self,col,order):
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.match_list=sorted(self.match_list,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.match_list.reverse()
		self.emit(SIGNAL("layoutChanged()"))

class BBMatchTable(QAbstractTableModel):
	def __init__(self,parent, database_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.match_list=[]

		if database_name:
			database = DarunGrimDatabase.Database(database_name)

			[matches,source_non_matched,target_non_matched]=database.GetBBMatchInfo()
			for (match_map,source_one_location_info,source_function_oli,target_one_location_info,target_function_oli) in matches:
				source_function_name=''

				if source_function_oli!=None:
					source_function_name=source_function_oli.name
				target_function_name=''
				if target_function_oli!=None:
					target_function_name=target_function_oli.name

				self.match_list.append([source_one_location_info.disasm_lines,
									target_one_location_info.disasm_lines,
									source_function_name,
									target_function_name,
									match_map.match_rate])

			for (one_location_info, function_one_location_info, match_function_one_location_info) in source_non_matched:
				function_name=''
				if function_one_location_info!=None:
					function_name=function_one_location_info.name

				match_function_name=''
				if match_function_one_location_info!=None:
					match_function_name=match_function_one_location_info.name

				self.match_list.append([one_location_info.disasm_lines,
									"",
									function_name,
									match_function_name,
									0])


			for (one_location_info, function_one_location_info, match_function_one_location_info) in target_non_matched:
				function_name=''
				if function_one_location_info!=None:
					function_name=function_one_location_info.name

				match_function_name=''
				if match_function_one_location_info!=None:
					match_function_name=match_function_one_location_info.name

				self.match_list.append(["",
									one_location_info.disasm_lines,
									match_function_name,
									function_name,
									0])
	def rowCount(self,parent):
		return len(self.match_list)
	
	def columnCount(self,parent):
		return 5

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.match_list[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Orig", "Patched", "Orig Func", "Patched Func", "Match"][col]
		return None

class BlockTable(QAbstractTableModel):
	def __init__(self,parent,database_name='',source_function_address=0, target_function_address=0, *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.match_list=[]
		self.full_match_list=[]
		self.ShowFullMatches=False

		if database_name:
			database = DarunGrimDatabase.Database(database_name)

			self.SourceMatchInfo={}
			self.TargetMatchInfo={}
			[match_hash, source_non_matches,target_non_matches]=database.GetBlockMatches( source_function_address, target_function_address )
			for ( source_address, ( target_address, match_rate ) ) in match_hash.items():
				if self.ShowFullMatches or match_rate<100:
					self.match_list.append([source_address, target_address, match_rate])
				self.full_match_list.append([source_address, target_address, match_rate])
				self.SourceMatchInfo[source_address]=[target_address, match_rate]
				self.TargetMatchInfo[target_address]=[source_address, match_rate]

			for non_match in source_non_matches:
				self.match_list.append([non_match, 0, 0])

			for non_match in target_non_matches:
				self.match_list.append([0, non_match, 0])

	def GetSourceMatchInfo(self):
		return self.SourceMatchInfo

	def GetTargetMatchInfo(self):
		return self.TargetMatchInfo

	def GetBlockAddresses(self,index):
		return [self.match_list[index][0], self.match_list[index][1]]

	def GetMatchAddresses(self,col,address):
		for (addr1,addr2,match_rate) in self.full_match_list:
			if col==0 and address==addr1:
				return addr2
			if col==1 and address==addr2:
				return addr1
		return None

	def rowCount(self,parent):
		return len(self.match_list)
	
	def columnCount(self,parent):
		return 3

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		value=self.match_list[index.row()][index.column()]
		if index.column()<2:
			if value==0:
				return ""
			return "%.8X" % value

		elif index.column()==2:
			if value==0:
				return "Non match"
			return "%d%%" % value

		return value

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Orig", "Patched", "Match"][col]
		return None

	def sort(self,col,order):
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.match_list=sorted(self.match_list,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.match_list.reverse()
		self.emit(SIGNAL("layoutChanged()"))

class NewDiffingDialog(QDialog):
	def __init__(self,parent=None):
		super(NewDiffingDialog,self).__init__(parent)
		self.setWindowTitle("New Diffing")

		self.Filenames={'Orig':'','Patched':'','Result':''}

		orig_button=QPushButton('Orig File:',self)
		orig_button.clicked.connect(self.getOrigFilename)
		self.orig_line=QLineEdit("")
		self.orig_line.setAlignment(Qt.AlignLeft)

		patched_button=QPushButton('Patched File:',self)
		patched_button.clicked.connect(self.getPatchedFilename)
		self.patched_line=QLineEdit("")
		self.patched_line.setAlignment(Qt.AlignLeft)	

		result_button=QPushButton('Result:',self)
		result_button.clicked.connect(self.getResultFilename)
		self.result_line=QLineEdit("")
		self.result_line.setAlignment(Qt.AlignLeft)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		buttonBox.accepted.connect(self.accept)
		buttonBox.rejected.connect(self.reject)

		main_layout=QGridLayout()
		main_layout.addWidget(orig_button,0,0)
		main_layout.addWidget(self.orig_line,0,1)
		main_layout.addWidget(patched_button,1,0)
		main_layout.addWidget(self.patched_line,1,1)
		main_layout.addWidget(result_button,2,0)
		main_layout.addWidget(self.result_line,2,1)
		main_layout.addWidget(buttonBox,3,1)
		self.setLayout(main_layout)

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(NewDiffingDialog,self).keyPressEvent(e)

	def getOrigFilename(self):
		filename=self.getFilename("Orig")
		self.orig_line.setText(filename)

	def getPatchedFilename(self):
		filename=self.getFilename("Patched")
		self.patched_line.setText(filename)

	def getResultFilename(self):
		filename=self.getFilename("Result")

		if filename[-4:0].lower()!='.dgf':
			filename+='.dgf'
			self.Filenames['Result']=filename
		self.result_line.setText(filename)

	def getFilename(self,type):
		(filename,filter)=QFileDialog.getOpenFileName(self,type)
		if filename:
			self.Filenames[type]=filename

		return filename

class FileStoreBrowserDialog(QDialog):
	ShowResultButton=False

	def __init__(self,parent=None,database_name='',darungrim_storage_dir=''):
		super(FileStoreBrowserDialog,self).__init__(parent)
		self.setWindowTitle("File Store Browser")

		self.FileStoreDir=darungrim_storage_dir
		self.InitVars()

		self.filesWidgetsTemplate=FileStoreBrowser.FilesWidgetsTemplate(self,database_name)
		self.filesWidgetsTemplate.setDarunGrimStore(self.FileStoreDir)

		orig_button=QPushButton('Orig File >> ',self)
		orig_button.clicked.connect(self.getOrigFilename)
		self.orig_line=QLineEdit("")
		self.orig_line.setAlignment(Qt.AlignLeft)

		patched_button=QPushButton('Patched File >> ',self)
		patched_button.clicked.connect(self.getPatchedFilename)
		self.patched_line=QLineEdit("")
		self.patched_line.setAlignment(Qt.AlignLeft)		

		if self.ShowResultButton:
			result_button=QPushButton('Result:',self)
			result_button.clicked.connect(self.getResultFilename)
			self.result_line=QLineEdit("")
			self.result_line.setAlignment(Qt.AlignLeft)

		name_label=QLabel('Name:')
		self.name_line=QLineEdit("")
		self.name_line.setAlignment(Qt.AlignLeft)

		description_label=QLabel('Description:')
		self.description_line=QLineEdit("")
		self.description_line.setAlignment(Qt.AlignLeft)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		buttonBox.accepted.connect(self.accept)
		buttonBox.rejected.connect(self.reject)

		bottom_layout=QGridLayout()
		bottom_layout.addWidget(orig_button,0,0)
		bottom_layout.addWidget(self.orig_line,0,1)
		bottom_layout.addWidget(patched_button,0,2)
		bottom_layout.addWidget(self.patched_line,0,3)

		if self.ShowResultButton:
			bottom_layout.addWidget(result_button,1,0)
			bottom_layout.addWidget(self.result_line,2,1)

		bottom_layout.addWidget(name_label,1,0)
		bottom_layout.addWidget(self.name_line,1,1)

		bottom_layout.addWidget(description_label,1,2)
		bottom_layout.addWidget(self.description_line,1,3)

		bottom_layout.addWidget(buttonBox,4,3)

		main_layout=QVBoxLayout()
		main_layout.addWidget(self.filesWidgetsTemplate.tab_widget)
		main_layout.addLayout(bottom_layout)
		self.setLayout(main_layout)

		self.resize(950,500)
		self.setWindowFlags(self.windowFlags()|Qt.WindowSystemMenuHint|Qt.WindowMinMaxButtonsHint)
		self.show()

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(FileStoreBrowserDialog,self).keyPressEvent(e)

	def InitVars(self):
		self.OrigFileID=0
		self.OrigFilename=''
		self.OrigFileSHA1=''
		self.PatchedFileID=0
		self.PatchedFilename=''
		self.PatchedFileSHA1=''
		self.ResultFilename=''

		self.Name=''
		self.Description=''

	def getOrigFilename(self):
		ret = self.filesWidgetsTemplate.getCurrentSelection()
		if ret!=None:
			self.OrigFileID=ret['id']
			self.OrigFilename=os.path.join(self.FileStoreDir,ret['filename'])
			self.OrigFileSHA1=ret['sha1']
			self.orig_line.setText(self.OrigFilename)

	def getPatchedFilename(self):
		ret = self.filesWidgetsTemplate.getCurrentSelection()
		if ret!=None:
			self.PatchedFileID=ret['id']
			self.PatchedFilename=os.path.join(self.FileStoreDir,ret['filename'])
			self.PatchedFileSHA1=ret['sha1']
			self.patched_line.setText(self.PatchedFilename)

	def getResultFilename(self):
		(filename,filter)=QFileDialog.getOpenFileName(self,"Result...")
		if filename:
			self.ResultFilename=str(filename.replace("/","\\"))
			if self.ResultFilename[-4:0].lower()!='.dgf':
				self.ResultFilename+='.dgf'
			self.result_line.setText(self.ResultFilename)

class SessionTable(QAbstractTableModel):
	def __init__(self,parent,database_name='',*args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.list=[]
		database=FileStoreDatabase.Database(database_name)
		for (session,src_tag,dst_tag) in database.GetSessions():
			src_tag_name=''
			dst_tag_name=''

			if src_tag!=None:
				src_tag_name=src_tag.tag

			if dst_tag!=None:
				dst_tag_name=dst_tag.tag

			src_filename=database.GetFileNameWithVersionByID(session.src)
			dst_filename=database.GetFileNameWithVersionByID(session.dst)
			description="%s - %s vs %s - %s" % (src_filename, src_tag_name, dst_filename, dst_tag_name)
			self.list.append([session.name, 
							session.description, 
							src_filename,
							src_tag_name,
							dst_filename,
							dst_tag_name,
							session.result,
							description])

	def GetFilename(self,row):
		return self.list[row][6]

	def GetDescription(self,row):
		return self.list[row][7]

	def rowCount(self,parent):
		return len(self.list)

	def columnCount(self,parent):
		return 6

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.list[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name", "Description", "Orig", "Tag", "Patched", "Tag"][col]
		return None

	def sort(self,col,order):
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.list=sorted(self.list,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.list.reverse()
		self.emit(SIGNAL("layoutChanged()"))

class SessionsDialog(QDialog):
	def __init__(self,parent=None,database_name=''):
		super(SessionsDialog,self).__init__(parent)
		self.setWindowTitle("Sessions")

		self.Filename=''
		view=QTableView()
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)

		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		self.SessionTableView=view

		self.SessionTable=SessionTable(self,database_name)
		self.SessionTableView.setModel(self.SessionTable)

		vlayout=QVBoxLayout()
		vlayout.addWidget(view)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		buttonBox.accepted.connect(self.accept)
		buttonBox.rejected.connect(self.reject)

		vlayout.addWidget(buttonBox)
		self.setLayout(vlayout)

		self.resize(800,400)
		self.setWindowFlags(self.windowFlags()|Qt.WindowSystemMenuHint|Qt.WindowMinMaxButtonsHint)
		self.show()

	def GetFilename(self):
		selection=self.SessionTableView.selectionModel()
		if selection!=None:
			for index in selection.selection().indexes():
				return self.SessionTable.GetFilename(index.row())
		return ''

	def GetDescription(self):
		selection=self.SessionTableView.selectionModel()
		if selection!=None:
			for index in selection.selection().indexes():
				return self.SessionTable.GetDescription(index.row())
		return ''

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name", "Description", "Orig", "Patched"][col]
		return None

class ServerInfoDialog(QDialog):
	def __init__(self,parent=None, port=0):
		super(ServerInfoDialog,self).__init__(parent)
		self.setWindowTitle("Server Information")

		port_label=QLabel('Port:',self)

		if port==0:
			port_text='None'
		else:
			port_text='%d' % port

		port_number_label=QLabel(port_text, self)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok)
		buttonBox.accepted.connect(self.accept)

		main_layout=QGridLayout()
		main_layout.addWidget(port_label,0,0)
		main_layout.addWidget(port_number_label,0,1)
		main_layout.addWidget(buttonBox,1,1)

		self.setLayout(main_layout)

class ConfigurationDialog(QDialog):
	def __init__(self,parent=None, file_store_dir='', data_files_dir='', ida_path='', ida64_path='', log_level=0):
		super(ConfigurationDialog,self).__init__(parent)
		self.setWindowTitle("Configuration")

		file_store_dir_button=QPushButton('FileSotre Dir:',self)
		file_store_dir_button.clicked.connect(self.getFileStoreDir)
		self.file_store_dir_line=QLineEdit("")
		self.file_store_dir_line.setAlignment(Qt.AlignLeft)
		self.file_store_dir_line.setMinimumWidth(250)
		self.file_store_dir_line.setText(file_store_dir)

		data_files_dir_button=QPushButton('Data Files Dir:',self)
		data_files_dir_button.clicked.connect(self.getDataFilesDir)
		self.data_files_dir_line=QLineEdit("")
		self.data_files_dir_line.setAlignment(Qt.AlignLeft)
		self.data_files_dir_line.setMinimumWidth(250)
		self.data_files_dir_line.setText(data_files_dir)

		ida_path_button=QPushButton('IDA Path:',self)
		ida_path_button.clicked.connect(self.getIDAPath)
		self.ida_path_line=QLineEdit(ida_path)
		self.ida_path_line.setAlignment(Qt.AlignLeft)
		self.ida_path_line.setMinimumWidth(250)
		self.ida_path_line.setText(ida_path)
		self.IDAPath=ida_path

		ida64_path_button=QPushButton('IDA64 Path:',self)
		ida64_path_button.clicked.connect(self.getIDA64Path)
		self.ida64_path_line=QLineEdit(ida64_path)
		self.ida64_path_line.setAlignment(Qt.AlignLeft)
		self.ida64_path_line.setMinimumWidth(250)
		self.ida64_path_line.setText(ida64_path)
		self.IDA64Path=ida64_path

		log_level_button=QLabel('Log Level:',self)
		self.log_level_line=QLineEdit("")
		self.log_level_line.setAlignment(Qt.AlignLeft)
		self.log_level_line.setMinimumWidth(250)
		self.log_level_line.setText('%d' % log_level)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		buttonBox.accepted.connect(self.accept)
		buttonBox.rejected.connect(self.reject)

		main_layout=QGridLayout()
		main_layout.addWidget(file_store_dir_button,0,0)
		main_layout.addWidget(self.file_store_dir_line,0,1)

		main_layout.addWidget(data_files_dir_button,2,0)
		main_layout.addWidget(self.data_files_dir_line,2,1)

		main_layout.addWidget(ida_path_button,3,0)
		main_layout.addWidget(self.ida_path_line,3,1)

		main_layout.addWidget(ida64_path_button,4,0)
		main_layout.addWidget(self.ida64_path_line,4,1)

		main_layout.addWidget(log_level_button,5,0)
		main_layout.addWidget(self.log_level_line,5,1)

		main_layout.addWidget(buttonBox,6,1)

		self.setLayout(main_layout)

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(ConfigurationDialog,self).keyPressEvent(e)

	def getFileStoreDir(self):
		dir_name=QFileDialog.getExistingDirectory(self,'FileStore Dir')
		if dir_name:
			self.file_store_dir_line.setText(dir_name)

	def getFileStoreDatabase(self):
		(filename,filter)=QFileDialog.getOpenFileName(self,'FileStore Database File')
		if filename:
			self.file_store_database_line.setText(filename)

	def getDataFilesDir(self):
		dir_name=QFileDialog.getExistingDirectory(self,'Data Files Dir')
		if dir_name:
			self.data_files_dir_line.setText(dir_name)

	def getIDAPath(self):
		(filename,filter)=QFileDialog.getOpenFileName(self,'IDA Path',filter="*.exe")
		if filename:
			self.ida_path_line.setText(filename)

	def getIDA64Path(self):
		(filename,filter)=QFileDialog.getOpenFileName(self,'IDA64 Path',filter="*.exe")
		if filename:
			self.ida64_path_line.setText(filename)

"""
class _Popen(multiprocessing.forking.Popen):
	def __init__(self,*args,**kw):
		if hasattr(sys,'frozen'):
			os.putenv('_MEIPASS2', sys._MEIPASS)

		try:
			super(_Popen, self).__init__(*args,**kw)
		finally:
			if hasattr(sys, 'frozen'):
				os.unsetenv('_MEIPASS2')

class Process(multiprocessing.Process):
	_Popen=_Popen

"""

def PerformDiffThread(src_filename, target_filename, result_filename, log_filename='', log_level=100, dbg_storage_dir='', is_src_target_storage=False ):
	if is_src_target_storage:
		darungrim=DarunGrimEngine.DarunGrim()
		darungrim.SetStorageNames(src_filename, target_filename)
	else:
		darungrim=DarunGrimEngine.DarunGrim(src_filename, target_filename)

	darungrim.SetDGFSotrage(dbg_storage_dir)
	if log_filename:
		darungrim.SetLogFile(log_filename,log_level)
	darungrim.PerformDiff(result_filename)

class LogTextBoxDialog(QDialog):
	def __init__(self,parent=None):
		super(LogTextBoxDialog,self).__init__(parent)
		self.setWindowTitle("Log")

		self.text=QTextEdit()
		self.text.setReadOnly(True)
		vlayout=QVBoxLayout()
		vlayout.addWidget(self.text)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Close)
		buttonBox.rejected.connect(self.reject)
		vlayout.addWidget(buttonBox)

		self.setLayout(vlayout)
		self.setWindowFlags(self.windowFlags()|Qt.WindowSystemMenuHint|Qt.WindowMinMaxButtonsHint)
		self.textLen=0

	def addText(self,text):
		if self.textLen> 1024*1024:
			self.text.clear()
			self.textLen=0
		self.text.append(text)
		self.textLen+=len(text)

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(LogTextBoxDialog,self).keyPressEvent(e)

class LogThread(QThread):
	data_read=Signal(object)

	def __init__(self,filename):
		QThread.__init__(self)
		self.filename=filename
		self.endLoop=False

	def run(self):
		fd=None
		while not self.endLoop:
			try:
				fd=open(self.filename,'rb')
				break
			except:
				pass

		if fd!=None:
			while not self.endLoop:
				data=fd.read()
				if data:
					self.data_read.emit(data)

			fd.close()

	def end(self):
		self.endLoop=True

class MainWindow(QMainWindow):
	UseDock=False
	ShowBBMatchTableView=False

	def __init__(self,database_name):
		super(MainWindow,self).__init__()
		self.setWindowTitle("DarunGrim 4")
		self.NonMaxGeometry=None

		self.DarunGrimEngine=DarunGrimEngine.DarunGrim(start_ida_listener=True)
		self.readSettings()

		# Menu
		self.createActions()
		self.createMenus()

		#Use dock? not yet
		if not self.UseDock:
			bottom_splitter=QSplitter()
			self.GraphSplitter=QSplitter()

		# Functions
		self.FunctionMatchTableView=QTableView()
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		self.FunctionMatchTableView.setVerticalHeader(vheader)
		self.FunctionMatchTableView.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		self.FunctionMatchTableView.setSortingEnabled(True)
		self.FunctionMatchTableView.setSelectionBehavior(QAbstractItemView.SelectRows)
		
		if self.ShowBBMatchTableView:
			self.BBMatchTableView=QTableView()
			vheader=QHeaderView(Qt.Orientation.Vertical)
			vheader.setResizeMode(QHeaderView.ResizeToContents)
			self.BBMatchTableView.setVerticalHeader(vheader)
			self.BBMatchTableView.horizontalHeader().setResizeMode(QHeaderView.Stretch)
			self.BBMatchTableView.setSortingEnabled(True)
			self.BBMatchTableView.setSelectionBehavior(QAbstractItemView.SelectRows)

		if self.UseDock:
			dock=QDockWidget("Functions",self)
			dock.setObjectName("Functions")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(self.FunctionMatchTableView)
			self.addDockWidget(Qt.BottomDockWidgetArea,dock)
		else:
			bottom_splitter.addWidget(self.FunctionMatchTableView)

		# Blocks
		self.BlockTableModel=BlockTable(self,database_name)
		self.BlockTableView=QTableView()
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		self.BlockTableView.setVerticalHeader(vheader)
		self.BlockTableView.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		self.BlockTableView.setSortingEnabled(True)
		self.BlockTableView.setModel(self.BlockTableModel)
		self.BlockTableView.setSelectionBehavior(QAbstractItemView.SelectRows)

		if self.UseDock:
			dock=QDockWidget("Blocks",self)
			dock.setObjectName("Blocks")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(self.BlockTableView)
			self.addDockWidget(Qt.BottomDockWidgetArea,dock)		
		else:
			bottom_splitter.addWidget(self.BlockTableView)

		bottom_splitter.setStretchFactor(0,1)
		bottom_splitter.setStretchFactor(1,0)

		# Function Graph
		self.OrigFunctionGraph=MyGraphicsView()
		self.OrigFunctionGraph.setRenderHints(QPainter.Antialiasing)

		if self.UseDock:
			dock=QDockWidget("Orig",self)
			dock.setObjectName("Orig")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(view)
			self.addDockWidget(Qt.TopDockWidgetArea,dock)
		else:
			self.GraphSplitter.addWidget(self.OrigFunctionGraph)

		# Function Graph
		self.PatchedFunctionGraph=MyGraphicsView()
		self.PatchedFunctionGraph.setRenderHints(QPainter.Antialiasing)

		if self.UseDock:
			dock=QDockWidget("Patched",self)
			dock.setObjectName("Patched")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(view)
			self.addDockWidget(Qt.TopDockWidgetArea,dock)
		else:
			self.GraphSplitter.addWidget(self.PatchedFunctionGraph)

		self.RefreshGraphViews()

		if not self.UseDock:
			virt_splitter=QSplitter()
			virt_splitter.setOrientation(Qt.Vertical)

			virt_splitter.addWidget(self.GraphSplitter)

			if self.ShowBBMatchTableView:
				tab_widget=QTabWidget()
				tab_widget.addTab(bottom_splitter,"Functions..")
				tab_widget.addTab(self.BBMatchTableView,"Basic blocks...")
				virt_splitter.addWidget(tab_widget)
			else:
				virt_splitter.addWidget(bottom_splitter)

			virt_splitter.setStretchFactor(0,1)
			virt_splitter.setStretchFactor(1,0)

			main_widget=QWidget()
			vlayout=QVBoxLayout()
			vlayout.addWidget(virt_splitter)
			main_widget.setLayout(vlayout)
			self.setCentralWidget(main_widget)
			self.show()

		self.LogDialog=LogTextBoxDialog()
		self.LogDialog.resize(800,600)
		
		self.clearAreas()
		if database_name:
			self.OpenDatabase(database_name)
		self.restoreUI()

	def RefreshGraphViews(self):
		if self.ShowGraphs==True:
			self.OrigFunctionGraph.show()
			self.PatchedFunctionGraph.show()
			self.GraphSplitter.show()
		else:
			self.OrigFunctionGraph.hide()
			self.PatchedFunctionGraph.hide()
			self.GraphSplitter.hide()

	def clearAreas(self):
		self.OrigFunctionGraph.clear()
		self.PatchedFunctionGraph.clear()

		self.FunctionMatchTable=FunctionMatchTable(self)
		self.FunctionMatchTableView.setModel(self.FunctionMatchTable)

		if self.ShowBBMatchTableView:
			self.BBMatchTable=BBMatchTable(self)
			self.BBMatchTableView.setModel(self.BBMatchTable)

		self.BlockTableModel=BlockTable(self)
		self.BlockTableView.setModel(self.BlockTableModel)

	def newFromFileStore(self):
		dialog=FileStoreBrowserDialog(database_name=self.FileStoreDatabase, darungrim_storage_dir=self.FileStoreDir)
		if dialog.exec_():
			result_filename='%s-%s.dgf' % (dialog.OrigFileSHA1, dialog.PatchedFileSHA1)
			log_filename='%s-%s.log' % (dialog.OrigFileSHA1, dialog.PatchedFileSHA1)

			self.StartPerformDiff(dialog.OrigFilename,
								dialog.PatchedFilename,
								os.path.join(self.DataFilesDir, result_filename),
								os.path.join(self.DataFilesDir, log_filename),
								debug=False
							)

			file_store_database=FileStoreDatabase.Database(self.FileStoreDatabase)
			file_store_database.AddSession(dialog.name_line.text(), dialog.description_line.text(), dialog.OrigFileID, dialog.PatchedFileID, result_filename)

	def openFromFileStore(self):
		dialog=SessionsDialog(database_name=self.FileStoreDatabase)
		if dialog.exec_():
			self.OpenDatabase(os.path.join(self.DataFilesDir, dialog.GetFilename()))
			self.setWindowTitle("DarunGrim 4 %s" % dialog.GetDescription())

	def new(self):
		dialog=NewDiffingDialog()
		if dialog.exec_():
			src_filename = str(dialog.Filenames['Orig'])
			target_filename = str(dialog.Filenames['Patched'])
			result_filename = str(dialog.Filenames['Result'])
			log_filename=result_filename+'.log'
			self.StartPerformDiff(src_filename,target_filename,result_filename,log_filename)


	def reanalyze(self):
		database = DarunGrimDatabase.Database(self.DatabaseName)
		[src_filename,target_filename] = database.GetDGFFileLocations()
		database.Close()
		del database

		result_filename=''
		if self.DatabaseName[-4:].lower()=='.dgf':
			prefix=self.DatabaseName[0:-4]
		else:
			prefix=self.DatabaseName

		i=0
		while True:
			result_filename=prefix+'-%d.dgf' % i
			if not os.path.isfile(result_filename):
				break
			i+=1

		log_filename=result_filename + '.log'

		self.StartPerformDiff(src_filename,
								target_filename,
								str(self.DatabaseName),
								log_filename=log_filename,
								is_src_target_storage=True,
								debug=False)

	def onTextBoxDataReady(self,data):
		self.LogDialog.addText(data)

	def StartPerformDiff(self,src_filename,target_filename,result_filename,log_filename='',is_src_target_storage=False, debug=False):
		self.clearAreas()

		if os.path.isfile(log_filename):
			os.unlink(log_filename)

		try:
			os.makedirs(os.path.dirname(result_filename))
		except:
			pass

		if debug:
			p=None
			PerformDiffThread(src_filename,target_filename,result_filename,log_level=self.LogLevel,dbg_storage_dir=self.DataFilesDir,is_src_target_storage=is_src_target_storage)
		else:
			p=Process(target=PerformDiffThread,args=(src_filename,target_filename,result_filename,log_filename,self.LogLevel,self.DataFilesDir,is_src_target_storage))
			p.start()

		if p!=None:
			self.LogDialog.show()

			log_thread=LogThread(log_filename)
			log_thread.data_read.connect(self.onTextBoxDataReady)
			log_thread.start()

			while True:
				time.sleep(0.01)
				if not p.is_alive():
					break

				qApp.processEvents()

			log_thread.end()

		self.OpenDatabase(result_filename)

	def open(self):
		(filename,filter)=QFileDialog.getOpenFileName(self,"Open...")
		if filename:
			self.clearAreas()
			self.OpenDatabase(filename)

	def OpenFolder(self,folder):
		try:
			subprocess.check_call(['explorer',  folder])
		except:
			pass

	def openOriginalFilesLocation(self):
		database = DarunGrimDatabase.Database(self.DatabaseName)
		[src_filename,target_filename]=database.GetFilesLocation()
		self.OpenFolder(os.path.dirname(src_filename))

	def openPatchedFilesLocation(self):
		database = DarunGrimDatabase.Database(self.DatabaseName)
		[src_filename,target_filename]=database.GetFilesLocation()
		self.OpenFolder(os.path.dirname(target_filename))

	def OpenIDA(self,filename):
		ida_filename=filename

		if filename[-4:].lower()!='.idb' and filename[-4:].lower()!='.i64':
			for path in [filename[0:-4] + '.idb', filename[0:-4] + '.i64']:
				if os.path.isfile(path):
					ida_filename=path
					break

		self.DarunGrimEngine.OpenIDA(ida_filename)

	def synchronizeIDA(self):
		database = DarunGrimDatabase.Database(self.DatabaseName)
		[src_filename,target_filename]=database.GetFilesLocation()
		
		self.DarunGrimEngine.SetSourceController(src_filename)
		self.DarunGrimEngine.SetTargetController(target_filename)
		self.OpenIDA(src_filename)
		self.OpenIDA(target_filename)

	def captureWindow(self):
		(filename,filter)=QFileDialog.getSaveFileName(self,'Save file', filter="*.png")
		if filename:
			pixmap=QPixmap.grabWidget(self)
			pixmap.save(filename,"png")

	def saveOrigGraph(self):
		(filename,filter)=QFileDialog.getSaveFileName(self,'Save file', filter="*.png")
		if filename:
			self.OrigFunctionGraph.SaveImg(filename)

	def savePatchedGraph(self):
		(filename,filter)=QFileDialog.getSaveFileName(self,'Save file', filter="*.png")
		if filename:
			self.PatchedFunctionGraph.SaveImg(filename)

	def toggleShowGraphs(self):
		if self.ShowGraphs==True:
			self.ShowGraphs=False
		else:
			self.ShowGraphs=True
		self.RefreshGraphViews()

	def toggleSyncrhonizeIDAUponOpening(self):
		if self.SyncrhonizeIDAUponOpening==True:
			self.SyncrhonizeIDAUponOpening=False
		else:
			self.SyncrhonizeIDAUponOpening=True

	def showConfiguration(self):
		dialog=ConfigurationDialog( file_store_dir=self.FileStoreDir, 
									data_files_dir=self.DataFilesDir,
									ida_path=self.IDAPath,
									ida64_path=self.IDA64Path,
									log_level=self.LogLevel
								)
		if dialog.exec_():
			self.FileStoreDir=dialog.file_store_dir_line.text()
			self.DataFilesDir=dialog.data_files_dir_line.text()
			self.FileStoreDatabase=os.path.join(self.DataFilesDir,'index.db')
			self.IDAPath=dialog.ida_path_line.text()
			self.IDA64Path=dialog.ida64_path_line.text()
			self.DarunGrimEngine.SetIDAPath(self.IDAPath)
			self.DarunGrimEngine.SetIDAPath(self.IDA64Path,True)
			self.LogLevel=int(dialog.log_level_line.text())

	def serverInfo(self):
		dialog=ServerInfoDialog(port=self.DarunGrimEngine.ListeningPort)
		dialog.exec_()

	def toggleStaysOnTop(self):
		if self.StaysOnTop==True:
			self.StaysOnTop=False
			self.hide()
			self.setWindowFlags(self.windowFlags()& ~Qt.WindowStaysOnTopHint)			
			self.show()
		else:
			self.StaysOnTop=True
			self.hide()
			self.setWindowFlags(self.windowFlags()|Qt.WindowStaysOnTopHint)
			self.show()

	def intallIDAPlugin(self):
		(ret,message)=self.DarunGrimEngine.InstallIDAPlugin('DarunGrimPlugin.plw')
		if not ret:
			msg_box=QMessageBox()
			msg_box.setText('Try to run the program with an Administrator privilege\n' + message)
			msg_box.exec_()

		else:
			msg_box=QMessageBox()
			msg_box.setText('Installation successful\n'+message)
			msg_box.exec_()

	def createActions(self):
		self.newAct = QAction("New Diffing...",
								self,
								shortcut=QKeySequence.New,
								statusTip="Create new diffing output",
								triggered=self.new
							)

		self.openAct = QAction("Open...",
								self,
								shortcut=QKeySequence.Open,
								statusTip="Open a dgf database",
								triggered=self.open
							)

		self.newFromFileStoreAct = QAction("New Diffing (FileStore)...",
								self,
								statusTip="Create new diffing output",
								triggered=self.newFromFileStore
							)

		self.openFromFileStoreAct = QAction("Open Diffing (FileStore)...",
								self,
								statusTip="Open diffing output",
								triggered=self.openFromFileStore
							)

		self.reanalyzeAct = QAction("Reanalyze...",
								self,
								shortcut=QKeySequence.Open,
								statusTip="Reanalyze current files",
								triggered=self.reanalyze
							)

		self.synchornizeIDAAct= QAction("Synchornize IDA",
								self,
								statusTip="Synchronize IDA",
								triggered=self.synchronizeIDA
							)

		self.openOriginalFilesLocationAct = QAction("Open Orininal Files Location",
								self,
								statusTip="Open original file location",
								triggered=self.openOriginalFilesLocation
							)

		self.openPatchedFilesLocationAct = QAction("Open Patched Files Location",
								self,
								statusTip="Open patched file location",
								triggered=self.openPatchedFilesLocation
							)

		self.captureWindowAct = QAction("Capture...",
								self,
								statusTip="Save patched graph",
								triggered=self.captureWindow
							)

		self.saveOrigGraphAct = QAction("Save orig graph...",
								self,
								statusTip="Save original graph",
								triggered=self.saveOrigGraph
							)

		self.savePatchedGraphAct = QAction("Save patched graph...",
								self,
								statusTip="Save patched graph",
								triggered=self.savePatchedGraph
							)

		self.showGraphsAct = QAction("Show graphs...",
								self,
								statusTip="Show graphs",
								triggered=self.toggleShowGraphs,
								checkable=True
							)
		
		self.showGraphsAct.setChecked(self.ShowGraphs)

		self.syncrhonizeIDAUponOpeningAct = QAction("Synchronize IDA upon opening...",
								self,
								statusTip="Synchronize IDA upon opening",
								triggered=self.toggleSyncrhonizeIDAUponOpening,
								checkable=True
							)
		self.syncrhonizeIDAUponOpeningAct.setChecked(self.SyncrhonizeIDAUponOpening)

		self.configurationAct = QAction("Configuration...",
								self,
								statusTip="Configuration",
								triggered=self.showConfiguration
							)

		self.serverInfoAct = QAction("Server...",
								self,
								statusTip="Server Info",
								triggered=self.serverInfo
							)

		self.staysOnTopAct = QAction("Statys on top...",
								self,
								statusTip="Server Info",
								triggered=self.toggleStaysOnTop,
								checkable=True
							)
		self.staysOnTopAct.setChecked(self.StaysOnTop)

		self.intallIDAPluginAct = QAction("Install IDA Plugin...",
								self,
								statusTip="Install IDA Plugin...",
								triggered=self.intallIDAPlugin
							)

	def createMenus(self):
		self.fileMenu = self.menuBar().addMenu("&File")
		self.fileMenu.addAction(self.newAct)
		self.fileMenu.addAction(self.openAct)
		self.fileMenu.addAction(self.newFromFileStoreAct)
		self.fileMenu.addAction(self.openFromFileStoreAct)
		self.fileMenu.addAction(self.reanalyzeAct)

		self.analysisMenu = self.menuBar().addMenu("&Analysis")

		self.analysisMenu.addAction(self.synchornizeIDAAct)
		self.analysisMenu.addAction(self.openOriginalFilesLocationAct)
		self.analysisMenu.addAction(self.openPatchedFilesLocationAct)
		
		self.analysisMenu.addAction(self.captureWindowAct)
		self.analysisMenu.addAction(self.saveOrigGraphAct)
		self.analysisMenu.addAction(self.savePatchedGraphAct)

		self.optionsMenu = self.menuBar().addMenu("&Options")
		self.optionsMenu.addAction(self.showGraphsAct)
		self.optionsMenu.addAction(self.syncrhonizeIDAUponOpeningAct)
		self.optionsMenu.addAction(self.staysOnTopAct)
		self.optionsMenu.addAction(self.configurationAct)
		self.optionsMenu.addAction(self.serverInfoAct)
		self.optionsMenu.addAction(self.intallIDAPluginAct)

	def OpenDatabase(self,databasename):
		self.DatabaseName=databasename

		self.FunctionMatchTable=FunctionMatchTable(self,self.DatabaseName)
		self.FunctionMatchTableView.setModel(self.FunctionMatchTable)
		selection=self.FunctionMatchTableView.selectionModel()
		if selection!=None:
			selection.selectionChanged.connect(self.handleFunctionMatchTableChanged)

		if self.ShowBBMatchTableView:
			self.BBMatchTable=BBMatchTable(self,self.DatabaseName)
			self.BBMatchTableView.setModel(self.BBMatchTable)
			selection=self.BBMatchTableView.selectionModel()
			if selection!=None:
				selection.selectionChanged.connect(self.handleBBMatchTableChanged)

		database = DarunGrimDatabase.Database(self.DatabaseName)
		self.setWindowTitle("DarunGrim 4 - %s" % (database.GetDescription()))

		if self.SyncrhonizeIDAUponOpening:
			self.synchronizeIDA()

	def ColorController(self, type, disasms, match_info):
		for (address,[end_address,disasm]) in disasms.items():
			if not match_info.has_key(address):
				#Red block
				self.DarunGrimEngine.ColorAddress(type, address, end_address+1, 0x0000FF)
			elif match_info[address][1]!=100:
				#Yellow block
				self.DarunGrimEngine.ColorAddress(type, address, end_address+1, 0x00FFFF)
		
	def handleFunctionMatchTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				[source_function_address, target_function_address] = self.FunctionMatchTable.GetFunctionAddresses(index.row())
				self.BlockTableModel=BlockTable(self,self.DatabaseName,source_function_address, target_function_address)
				self.BlockTableView.setModel(self.BlockTableModel)
				selection=self.BlockTableView.selectionModel()
				if selection!=None:
					selection.selectionChanged.connect(self.handleBlockTableChanged)

				database=DarunGrimDatabase.Database(self.DatabaseName)

				(source_disasms, source_links) = database.GetFunctionDisasmLines("Source", source_function_address)
				(target_disasms, target_links) = database.GetFunctionDisasmLines("Target", target_function_address)

				source_match_info=self.BlockTableModel.GetSourceMatchInfo()
				target_match_info=self.BlockTableModel.GetTargetMatchInfo()

				#IDA Sync
				self.ColorController(0, source_disasms, source_match_info )
				self.ColorController(1, target_disasms, target_match_info )
				self.DarunGrimEngine.JumpToAddresses(source_function_address, target_function_address)

				if self.ShowGraphs:
					# Draw graphs
					self.OrigFunctionGraph.SetDatabaseName(self.DatabaseName)
					self.OrigFunctionGraph.DrawFunctionGraph("Source", source_function_address, source_disasms, source_links, source_match_info)
					self.OrigFunctionGraph.SetSelectBlockCallback(self.SelectedBlock)
					self.OrigFunctionGraph.HilightAddress(source_function_address)

					self.PatchedFunctionGraph.SetDatabaseName(self.DatabaseName)
					self.PatchedFunctionGraph.DrawFunctionGraph("Target", target_function_address, target_disasms, target_links, target_match_info)
					self.PatchedFunctionGraph.SetSelectBlockCallback(self.SelectedBlock)
					self.PatchedFunctionGraph.HilightAddress(target_function_address)

				break

	def handleBBMatchTableChanged(self,selected,dselected):
		pass

	def handleBlockTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				[orig_address,patched_address]=self.BlockTableModel.GetBlockAddresses(index.row())

				if self.ShowGraphs:
					if orig_address!=0:
						self.OrigFunctionGraph.HilightAddress(orig_address)

					if patched_address!=0:
						self.PatchedFunctionGraph.HilightAddress(patched_address)

				self.DarunGrimEngine.JumpToAddresses(orig_address, patched_address)
				break

	def SelectedBlock(self,graph,address):
		if graph==self.OrigFunctionGraph:
			matched_address=self.BlockTableModel.GetMatchAddresses(0,address)
			if matched_address!=None:
				self.PatchedFunctionGraph.HilightAddress(matched_address)
				self.DarunGrimEngine.JumpToAddresses(0, matched_address)

		elif graph==self.PatchedFunctionGraph:
			matched_address=self.BlockTableModel.GetMatchAddresses(1,address)
			if matched_address!=None:
				self.OrigFunctionGraph.HilightAddress(matched_address)
				self.DarunGrimEngine.JumpToAddresses(matched_address, 0)

	def changeEvent(self,event):
		if event.type()==QEvent.WindowStateChange:
			if (self.windowState()&Qt.WindowMinimized)==0 and \
				 (self.windowState()&Qt.WindowMaximized)==0 and \
				 (self.windowState()&Qt.WindowFullScreen)==0 and \
				 (self.windowState()&Qt.WindowActive)==0:
					pass

	def resizeEvent(self,event):
		if not self.isMaximized():
			self.NonMaxGeometry=self.saveGeometry()

	def restoreUI(self):
		settings=QSettings("DarunGrim LLC", "DarunGrim")
			
		if settings.contains("geometry/non_max"):
			self.NonMaxGeometry=settings.value("geometry/non_max")
			self.restoreGeometry(self.NonMaxGeometry)
		else:	
			self.NonMaxGeometry=self.saveGeometry()
		
		if settings.contains("isMaximized"):
			if settings.value("isMaximized")=="true":
				self.setWindowState(self.windowState()|Qt.WindowMaximized)
		self.restoreState(settings.value("windowState"))

	def readSettings(self):
		settings=QSettings("DarunGrim LLC", "DarunGrim")
		self.ShowGraphs=True
		if settings.contains("General/ShowGraphs"):
			if settings.value("General/ShowGraphs")=='true':
				self.ShowGraphs=True
			else:
				self.ShowGraphs=False

		self.SyncrhonizeIDAUponOpening=False
		if settings.contains("General/SyncrhonizeIDAUponOpening"):
			if settings.value("General/SyncrhonizeIDAUponOpening")=='true':
				self.SyncrhonizeIDAUponOpening=True
			else:
				self.SyncrhonizeIDAUponOpening=False

		self.StaysOnTop=False
		if settings.contains("General/StaysOnTop"):
			if settings.value("General/StaysOnTop")=='true':
				self.StaysOnTop=True
			else:
				self.StaysOnTop=False

		if self.StaysOnTop==True:
			self.setWindowFlags(self.windowFlags()|Qt.WindowStaysOnTopHint)			
		else:
			self.setWindowFlags(self.windowFlags()& ~Qt.WindowStaysOnTopHint)

		self.FileStoreDir = "Z:\\DarunGrimStore"
		if settings.contains("General/FileStoreDir"):
			self.FileStoreDir=settings.value("General/FileStoreDir")
		
		self.FileStoreDatabase='index.db'
		if settings.contains("General/FileStoreDatabase"):
			self.FileStoreDatabase=settings.value("General/FileStoreDatabase")

		self.DataFilesDir='C:\\mat\\DarunGrimDGFs'
		if settings.contains("General/DataFilesDir"):
			self.DataFilesDir=settings.value("General/DGFSotreDir")

		self.IDAPath=''
		if settings.contains("General/IDAPath"):
			self.IDAPath=settings.value("General/IDAPath")
		else:
			files=self.DarunGrimEngine.LocateIDAExecutables()
			if len(files)>0:
				self.IDAPath=files[0][0]
		
		self.DarunGrimEngine.SetIDAPath(self.IDAPath)

		if not self.DarunGrimEngine.CheckIDAPlugin():
			print 'DarunGrim plugin is missing'

		self.IDA64Path=''
		if settings.contains("General/IDA64Path"):
			self.IDAPath=settings.value("General/IDA64Path")
		else:
			files=self.DarunGrimEngine.LocateIDAExecutables(is_64=True)
			if len(files)>0:
				self.IDA64Path=files[0][0]

		self.DarunGrimEngine.SetIDAPath(self.IDA64Path,is_64=True)

		self.LogLevel=10
		if settings.contains("General/LogLevel"):
			self.LogLevel=int(settings.value("General/LogLevel"))

	def saveSettings(self):
		settings = QSettings("DarunGrim LLC", "DarunGrim")
		settings.setValue("General/ShowGraphs", self.ShowGraphs)
		settings.setValue("General/SyncrhonizeIDAUponOpening", self.SyncrhonizeIDAUponOpening)
		settings.setValue("General/StaysOnTop", self.StaysOnTop)
		settings.setValue("General/FileStoreDir", self.FileStoreDir)
		settings.setValue("General/FileStoreDatabase", self.FileStoreDatabase)
		settings.setValue("General/DGFSotreDir", self.DataFilesDir)
		settings.setValue("General/LogLevel", self.LogLevel)

		if self.NonMaxGeometry!=None:
			settings.setValue("geometry/non_max", self.NonMaxGeometry)
		settings.setValue("isMaximized", self.isMaximized())
		settings.setValue("windowState", self.saveState())

	def closeEvent(self, event):
		self.saveSettings()
		QMainWindow.closeEvent(self, event)

if __name__=='__main__':
	multiprocessing.freeze_support()
	import sys

	if len(sys.argv)>1:
		database_name=sys.argv[1]
	else:
		database_name=''

	app=QApplication(sys.argv)
	mainWindow=MainWindow(database_name)
	mainWindow.show()
	sys.exit(app.exec_())
