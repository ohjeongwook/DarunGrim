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
from multiprocessing import Process
import time
import os
import operator

class FunctionMatchTable(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.match_list=[]

		if database_name:
			self.database = DarunGrimDatabase.Database(database_name)

			for function_match_info in self.database.GetFunctionMatchInfo():
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
										str( function_match_info.match_rate),
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
			self.database = DarunGrimDatabase.Database(database_name)

			[matches,source_non_matched,target_non_matched]=self.database.GetBBMatchInfo()
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

class BlockMatchTable(QAbstractTableModel):
	def __init__(self,parent, *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.match_list=[]

	def GetBlockAddresses(self,index):
		return [self.match_list[index][0], self.match_list[index][1]]

	def GetMatchAddresses(self,col,address):
		for (addr1,addr2,match_rate) in self.match_list:
			if col==0 and address==addr1:
				return addr2
			if col==1 and address==addr2:
				return addr1
		return None

	def ShowFunctionAddresses(self,match_list):
		self.match_list=match_list
		self.dataChanged.emit(0, len(self.match_list))

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
			return "%.8X" % value

		elif index.column()==2:
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
		dialog=QFileDialog()
		filename=''
		if dialog.exec_():
			filename=dialog.selectedFiles()[0]
			self.Filenames[type]=filename

		return filename

class FileStoreBrowserDialog(QDialog):
	ShowResultButton=False

	def __init__(self,parent=None,database_name='',darungrim_storage_dir=''):
		super(FileStoreBrowserDialog,self).__init__(parent)
		
		self.DarunGrimStorageDir=darungrim_storage_dir
		self.InitVars()

		self.filesWidgetsTemplate=FileStoreBrowser.FilesWidgetsTemplate(self,database_name)
		self.filesWidgetsTemplate.setDarunGrimStore(self.DarunGrimStorageDir)

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

		self.resize(900,500)
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

	def pressedOK(self):
		self.Name=self.name_line.text()
		self.Description=self.description_line.text()
		self.close()

	def pressedCancel(self):
		self.InitVars()
		self.close()

	def getOrigFilename(self):
		ret = self.filesWidgetsTemplate.getCurrentSelection()
		if ret!=None:
			self.OrigFileID=ret['id']
			self.OrigFilename=os.path.join(self.DarunGrimStorageDir,ret['filename'])
			self.OrigFileSHA1=ret['sha1']
			self.orig_line.setText(self.OrigFilename)

	def getPatchedFilename(self):
		ret = self.filesWidgetsTemplate.getCurrentSelection()
		if ret!=None:
			self.PatchedFileID=ret['id']
			self.PatchedFilename=os.path.join(self.DarunGrimStorageDir,ret['filename'])
			self.PatchedFileSHA1=ret['sha1']
			self.patched_line.setText(self.PatchedFilename)

	def getResultFilename(self):
		dialog=QFileDialog()
		if dialog.exec_():
			filename=dialog.selectedFiles()[0]
			self.ResultFilename=str(filename.replace("/","\\"))
			if self.ResultFilename[-4:0].lower()!='.dgf':
				self.ResultFilename+='.dgf'
			self.result_line.setText(self.ResultFilename)

class SessionTable(QAbstractTableModel):
	def __init__(self,parent,database_name='',*args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.list=[]
		database=FileStoreDatabase.Database(database_name)
		for session in database.GetSessions():
			self.list.append([session.name, 
							session.description, 
							database.GetFileNameWithVersionByID(session.src),
							database.GetFileNameWithVersionByID(session.dst),
							session.result])

	def GetFilename(self,row):
		return self.list[row][4]

	def rowCount(self,parent):
		return len(self.list)

	def columnCount(self,parent):
		return 4

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.list[index.row()][index.column()]

	def headerDAta(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name", "Description", "Orig", "Patched"][col]
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

		self.Filename=''
		view=QTableView()
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.Stretch)
		view.setVerticalHeader(vheader)

		self.session_table_view=view

		self.session_table_model=SessionTable(self,database_name)
		self.session_table_view.setModel(self.session_table_model)

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
		selection=self.session_table_view.selectionModel()
		if selection!=None:
			for index in selection.selection().indexes():
				return self.session_table_model.GetFilename(index.row())
		return ''

def PerformDiff(src_filename,target_filename,result_filename,log_filename='',log_level=100,dbg_storage_dir=''):
	darungrim=DarunGrimEngine.DarunGrim(src_filename, target_filename)
	darungrim.SetDGFSotrage(dbg_storage_dir)
	if log_filename:
		darungrim.SetLogFile(log_filename,log_level)
	darungrim.PerformDiff(result_filename)

class LogTextBoxDialog(QDialog):
	def __init__(self,parent=None):
		super(LogTextBoxDialog,self).__init__(parent)

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
		while not self.endLoop:
			try:
				fd=open(self.filename,'rb')
				break
			except:
				pass

		while not self.endLoop:
			data=fd.read()
			if data:
				self.data_read.emit(data)

		fd.close()

	def end(self):
		self.endLoop=True

class MainWindow(QMainWindow):
	UseDock=False

	def __init__(self,database_name):
		super(MainWindow,self).__init__()
		self.setWindowTitle("DarunGrim 4")

		# Menu
		self.createActions()
		self.createMenus()

		#Use dock? not yet
		if not self.UseDock:
			bottom_splitter=QSplitter()
			graph_splitter=QSplitter()

		# Functions
		self.functions_match_table_view=QTableView()
		self.functions_match_table_view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		self.functions_match_table_view.setSortingEnabled(True)
		self.functions_match_table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
		
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		self.functions_match_table_view.setVerticalHeader(vheader)

		self.bb_match_table_view=QTableView()
		self.bb_match_table_view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		self.bb_match_table_view.setSortingEnabled(True)
		self.bb_match_table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
		
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		self.bb_match_table_view.setVerticalHeader(vheader)

		if database_name:
			self.OpenDatabase(database_name)
				
		if self.UseDock:
			dock=QDockWidget("Functions",self)
			dock.setObjectName("Functions")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(self.functions_match_table_view)
			self.addDockWidget(Qt.BottomDockWidgetArea,dock)
		else:
			bottom_splitter.addWidget(self.functions_match_table_view)

		# Blocks
		self.block_table_model=BlockMatchTable(self)
		self.block_table_view=QTableView()
		self.block_table_view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		self.block_table_view.setSortingEnabled(True)
		self.block_table_view.setModel(self.block_table_model)
		self.block_table_view.setSelectionBehavior(QAbstractItemView.SelectRows)
		
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		self.block_table_view.setVerticalHeader(vheader)

		if self.UseDock:
			dock=QDockWidget("Blocks",self)
			dock.setObjectName("Blocks")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(self.block_table_view)
			self.addDockWidget(Qt.BottomDockWidgetArea,dock)		
		else:
			bottom_splitter.addWidget(self.block_table_view)

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
			graph_splitter.addWidget(self.OrigFunctionGraph)

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
			graph_splitter.addWidget(self.PatchedFunctionGraph)

		if not self.UseDock:
			virt_splitter=QSplitter()
			virt_splitter.setOrientation(Qt.Vertical)

			virt_splitter.addWidget(graph_splitter)


			tab_widget=QTabWidget()
			tab_widget.addTab(bottom_splitter,"Functions..")
			tab_widget.addTab(self.bb_match_table_view,"Basic blocks...")

			virt_splitter.addWidget(tab_widget)

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

		self.readSettings()

	def clearAreas(self):
		self.OrigFunctionGraph.clear()
		self.PatchedFunctionGraph.clear()

		self.functions_match_table_model=FunctionMatchTable(self)
		self.functions_match_table_view.setModel(self.functions_match_table_model)

		self.bb_match_table_model=BBMatchTable(self)
		self.bb_match_table_view.setModel(self.bb_match_table_model)

		self.block_table_model=BlockMatchTable(self)
		self.block_table_view.setModel(self.block_table_model)

	def newFromFileStore(self):
		dialog=FileStoreBrowserDialog(database_name=self.FileStoreDatabase, darungrim_storage_dir=self.DarunGrimStorageDir)
		if dialog.exec_():
			result_filename='%s-%s.dgf' % (dialog.OrigFileSHA1, dialog.PatchedFileSHA1)
			log_filename='%s-%s.log' % (dialog.OrigFileSHA1, dialog.PatchedFileSHA1)

			self.StartPerformDiff(dialog.OrigFilename,
								dialog.PatchedFilename,
								os.path.join(self.DarunGrimDGFDir, result_filename),
								os.path.join(self.DarunGrimDGFDir, log_filename)
							)

			file_store_database=FileStoreDatabase.Database(self.FileStoreDatabase)
			file_store_database.AddSession(dialog.Name, dialog.Description, dialog.OrigFileID, dialog.PatchedFileID, result_filename)

	def openFromFileStore(self):
		dialog=SessionsDialog(database_name=self.FileStoreDatabase)
		if dialog.exec_():
			self.OpenDatabase(os.path.join(self.DarunGrimDGFDir, dialog.GetFilename()))

	def new(self):
		dialog=NewDiffingDialog()
		if dialog.exec_():
			src_filename = str(dialog.Filenames['Orig'])
			target_filename = str(dialog.Filenames['Patched'])
			result_filename = str(dialog.Filenames['Result'])
			log_filename=result_filename+'.log'
			self.StartPerformDiff(src_filename,target_filename,result_filename)

	def onTextBoxDataReady(self,data):
		self.LogDialog.addText(data)

	def StartPerformDiff(self,src_filename,target_filename,result_filename,log_filename='',debug=False):
		self.clearAreas()

		if os.path.isfile(log_filename):
			os.unlink(log_filename)

		try:
			os.makedirs(os.path.dirname(result_filename))
		except:
			pass

		if debug:
			print 'PerformDiff: ', src_filename,target_filename,result_filename
			p=None
			PerformDiff(src_filename,target_filename,result_filename,log_level=self.LogLevel,dbg_storage_dir=self.DarunGrimDGFDir)
		else:
			p=Process(target=PerformDiff,args=(src_filename,target_filename,result_filename,log_filename,self.LogLevel,self.DarunGrimDGFDir))
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
		dialog=QFileDialog()
		if dialog.exec_():
			self.clearAreas()
			self.OpenDatabase(dialog.selectedFiles()[0])

	def saveOrigGraph(self):
		dialog=QFileDialog()
		if dialog.exec_():
			self.OrigFunctionGraph.SaveImg(dialog.selectedFiles()[0])

	def savePatchedGraph(self):
		dialog=QFileDialog()
		if dialog.exec_():
			self.PatchedFunctionGraph.SaveImg(dialog.selectedFiles()[0])

	def createActions(self):
		self.newAct = QAction("New Diffing...",self,shortcut=QKeySequence.New,statusTip="Create new diffing output",triggered=self.new)
		self.openAct = QAction("Open...",self,shortcut=QKeySequence.Open,statusTip="Open a dgf database",triggered=self.open)

		self.newFromFileStoreAct = QAction("New Diffing (FileStore)...",self,shortcut=QKeySequence.New,statusTip="Create new diffing output",triggered=self.newFromFileStore)
		self.openFromFileStoreAct = QAction("Open Diffing (FileStore)...",self,shortcut=QKeySequence.New,statusTip="Open diffing output",triggered=self.openFromFileStore)

		self.saveOrigGraphAct = QAction("Save orig graph...",self,shortcut=QKeySequence.Open,statusTip="Save original graph",triggered=self.saveOrigGraph)
		self.savePatchedGraphAct = QAction("Save patched graph...",self,shortcut=QKeySequence.Open,statusTip="Save patched graph",triggered=self.savePatchedGraph)

	def createMenus(self):
		self.fileMenu = self.menuBar().addMenu("&File")
		self.fileMenu.addAction(self.newAct)
		self.fileMenu.addAction(self.openAct)
		self.fileMenu.addAction(self.newFromFileStoreAct)
		self.fileMenu.addAction(self.openFromFileStoreAct)
		self.fileMenu.addAction(self.saveOrigGraphAct)
		self.fileMenu.addAction(self.savePatchedGraphAct)

	def OpenDatabase(self,databasename):
		self.DatabaseName=databasename

		self.functions_match_table_model=FunctionMatchTable(self,self.DatabaseName)
		self.functions_match_table_view.setModel(self.functions_match_table_model)
		selection=self.functions_match_table_view.selectionModel()
		if selection!=None:
			selection.selectionChanged.connect(self.handleFunctionMatchTableChanged)

		self.bb_match_table_model=BBMatchTable(self,self.DatabaseName)
		self.bb_match_table_view.setModel(self.bb_match_table_model)
		selection=self.bb_match_table_view.selectionModel()
		if selection!=None:
			selection.selectionChanged.connect(self.handleBBMatchTableChanged)
		
	def handleFunctionMatchTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				[source_function_address, target_function_address] = self.functions_match_table_model.GetFunctionAddresses(index.row())
				database = DarunGrimDatabase.Database(self.DatabaseName)

				match_list=[]
				source_match_info={}
				target_match_info={}
				for ( source_address, ( target_address, match_rate ) ) in database.GetBlockMatches( source_function_address, target_function_address ):
					match_list.append([source_address, target_address, match_rate])
					source_match_info[source_address]=[target_address, match_rate]
					target_match_info[target_address]=[source_address, match_rate]

				self.block_table_model=BlockMatchTable(self)
				self.block_table_model.ShowFunctionAddresses(match_list)
				self.block_table_view.setModel(self.block_table_model)
				
				selection=self.block_table_view.selectionModel()
				if selection!=None:
					selection.selectionChanged.connect(self.handleBlockTableChanged)

				# Draw graphs
				self.OrigFunctionGraph.SetDatabaseName(self.DatabaseName)
				self.OrigFunctionGraph.DrawFunctionGraph("Source", source_function_address, source_match_info)
				self.OrigFunctionGraph.SetSelectBlockCallback(self.SelectedBlock)
				self.PatchedFunctionGraph.SetDatabaseName(self.DatabaseName)
				self.PatchedFunctionGraph.DrawFunctionGraph("Target", target_function_address, target_match_info)
				self.PatchedFunctionGraph.SetSelectBlockCallback(self.SelectedBlock)

				break

	def handleBBMatchTableChanged(self,selected,dselected):
		pass

	def handleBlockTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				[orig_address,patched_address]=self.block_table_model.GetBlockAddresses(index.row())
				self.OrigFunctionGraph.HilightAddress(orig_address)
				self.PatchedFunctionGraph.HilightAddress(patched_address)

				break

	def SelectedBlock(self,graph,address):
		if graph==self.OrigFunctionGraph:
			matched_address=self.block_table_model.GetMatchAddresses(0,address)
			if matched_address!=None:
				self.PatchedFunctionGraph.HilightAddress(matched_address)

		elif graph==self.PatchedFunctionGraph:
			matched_address=self.block_table_model.GetMatchAddresses(1,address)
			if matched_address!=None:
				self.OrigFunctionGraph.HilightAddress(matched_address)

	def readSettings(self):
		settings=QSettings("DarunGrim LLC", "DarunGrim")
		
		if settings.contains("geometry"):
			self.restoreGeometry(settings.value("geometry"))
		else:
			self.resize(800,600)

		self.restoreState(settings.value("windowState"))

		self.DarunGrimStorageDir = "Z:\\DarunGrimStore" #TOOD:
		self.FileStoreDatabase='index.db'
		self.DarunGrimDGFDir='C:\\mat\\DarunGrimDGFs'
		self.LogLevel=100

	def closeEvent(self, event):
		settings = QSettings("DarunGrim LLC", "DarunGrim")
		settings.setValue("geometry", self.saveGeometry())
		settings.setValue("geometry/functions_match_table_view", self.functions_match_table_view.saveGeometry())
		settings.setValue("geometry/bb_match_table_view", self.bb_match_table_view.saveGeometry())
		settings.setValue("geometry/block_table_view", self.block_table_view.saveGeometry())
		settings.setValue("windowState", self.saveState())
		QMainWindow.closeEvent(self, event)

if __name__=='__main__':
	import sys

	if len(sys.argv)>1:
		database_name=sys.argv[1]
	else:
		database_name=''

	app=QApplication(sys.argv)
	mainWindow=MainWindow(database_name)
	mainWindow.show()
	sys.exit(app.exec_())
