from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *
import DarunGrimDatabase
import DiffEngine
from Graphs import *
import FlowGrapher
import FileStoreBrowser
import DarunGrimEngine

import pprint
from multiprocessing import Process
import time
import os

def PerformDiff(src_filename,target_filename,result_filename):
	darungrim=DarunGrimEngine.DarunGrim(src_filename, target_filename)
	darungrim.SetDGFSotrage(os.getcwd())
	darungrim.PerformDiff(result_filename)

class FunctionMatchTable(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.match_list=[]
		self.full_fmi_list=[]

		if database_name:
			self.database = DarunGrimDatabase.Database(database_name)

			for function_match_info in self.database.GetFunctionMatchInfo():
				if function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
					#print function_match_info.id, function_match_info.source_file_id, function_match_info.target_file_id, function_match_info.end_address, 
			
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
										str( function_match_info.match_rate)])

					self.full_fmi_list.append(function_match_info)

	def GetFunctionAddresses(self,index):
		return [self.full_fmi_list[index].source_address, self.full_fmi_list[index].target_address]

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
		pass

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
		pass

class NewDiffingDialog(QDialog):
	def __init__(self,parent=None):
		super(NewDiffingDialog,self).__init__(parent)

		self.Filenames={}

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

		ok_button=QPushButton('OK',self)
		ok_button.clicked.connect(self.pressedOK)
		cancel_button=QPushButton('Cancel',self)
		cancel_button.clicked.connect(self.pressedCancel)

		main_layout=QGridLayout()
		main_layout.addWidget(orig_button,0,0)
		main_layout.addWidget(self.orig_line,0,1)
		main_layout.addWidget(patched_button,1,0)
		main_layout.addWidget(self.patched_line,1,1)
		main_layout.addWidget(result_button,2,0)
		main_layout.addWidget(self.result_line,2,1)
		main_layout.addWidget(ok_button,3,0)
		main_layout.addWidget(cancel_button,3,1)
		self.setLayout(main_layout)

	def pressedOK(self):
		self.close()

	def pressedCancel(self):
		self.Filenames.clear()
		self.close()

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
		self.OrigFilename=''
		self.OrigFileSHA1=''
		self.PatchedFilename=''
		self.PatchedFileSHA1=''
		self.ResultFilename=''

		self.filesWidgetsTemplate=FileStoreBrowser.FilesWidgetsTemplate(self,database_name)

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

		ok_button=QPushButton('OK',self)
		ok_button.clicked.connect(self.pressedOK)
		cancel_button=QPushButton('Cancel',self)
		cancel_button.clicked.connect(self.pressedCancel)

		bottom_layout=QGridLayout()
		bottom_layout.addWidget(orig_button,0,0)
		bottom_layout.addWidget(self.orig_line,0,1)
		bottom_layout.addWidget(patched_button,1,0)
		bottom_layout.addWidget(self.patched_line,1,1)

		if self.ShowResultButton:
			bottom_layout.addWidget(result_button,2,0)
			bottom_layout.addWidget(self.result_line,2,1)
		bottom_layout.addWidget(ok_button,3,0)
		bottom_layout.addWidget(cancel_button,3,1)

		main_layout=QVBoxLayout()
		main_layout.addWidget(self.filesWidgetsTemplate.tab_widget)
		main_layout.addLayout(bottom_layout)
		self.setLayout(main_layout)
		self.show()

	def pressedOK(self):
		self.close()

	def pressedCancel(self):
		self.close()

	def getOrigFilename(self):
		[filename,sha1] = self.filesWidgetsTemplate.getCurrentSelection()
		self.OrigFilename=os.path.join(self.DarunGrimStorageDir,filename)
		self.OrigFileSHA1=sha1
		self.orig_line.setText(self.OrigFilename)

	def getPatchedFilename(self):
		[filename,sha1] = self.filesWidgetsTemplate.getCurrentSelection()
		self.PatchedFilename=os.path.join(self.DarunGrimStorageDir,filename)
		self.PatchedFileSHA1=sha1
		self.patched_line.setText(self.PatchedFilename)

	def getResultFilename(self):
		dialog=QFileDialog()
		if dialog.exec_():
			filename=dialog.selectedFiles()[0]
			self.ResultFilename=str(filename.replace("/","\\"))
			if self.ResultFilename[-4:0].lower()!='.dgf':
				self.ResultFilename+='.dgf'
			self.result_line.setText(self.ResultFilename)

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
		view=QTableView()
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)

		self.functions_match_table_view=view

		if database_name:
			self.OpenDatabase(database_name)
		if self.UseDock:
			dock=QDockWidget("Functions",self)
			dock.setObjectName("Functions")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(view)
			self.addDockWidget(Qt.BottomDockWidgetArea,dock)
		else:
			bottom_splitter.addWidget(view)

		# Blocks
		self.block_table_model=BlockMatchTable(self)
		view=QTableView()
		view.setModel(self.block_table_model)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)
		
		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)
		self.block_table_view=view

		if self.UseDock:
			dock=QDockWidget("Blocks",self)
			dock.setObjectName("Blocks")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(view)
			self.addDockWidget(Qt.BottomDockWidgetArea,dock)		
		else:
			bottom_splitter.addWidget(view)

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
			virt_splitter.addWidget(bottom_splitter)

			virt_splitter.setStretchFactor(0,1)
			virt_splitter.setStretchFactor(1,0)

			main_widget=QWidget()
			vlayout=QVBoxLayout()
			vlayout.addWidget(virt_splitter)
			main_widget.setLayout(vlayout)
			self.setCentralWidget(main_widget)
			self.show()

		self.readSettings()
		self.DarunGrimStorageDir = "Z:\\DarunGrimStore" #TOOD:]

	def clearAreas(self):
		self.OrigFunctionGraph.clear()
		self.PatchedFunctionGraph.clear()

		self.functions_match_table_model=FunctionMatchTable(self)
		self.functions_match_table_view.setModel(self.functions_match_table_model)

		self.block_table_model=BlockMatchTable(self)
		self.block_table_view.setModel(self.block_table_model)

	def new_from_file_store(self):
		self.FileIndexDB='index.db'
		self.DarunGrimDGFDir='z:\\DarunGrimDGFStore'
		dialog=FileStoreBrowserDialog(database_name=self.FileIndexDB, darungrim_storage_dir=self.DarunGrimStorageDir)
		dialog.exec_()

		if len(dialog.OrigFilename) and len(dialog.PatchedFilename):
			result_filename = os.path.join(self.DarunGrimDGFDir, '%s-%s.dgf' % (dialog.OrigFileSHA1, dialog.PatchedFileSHA1))

			self.StartPerformDiff(dialog.OrigFilename,
								dialog.PatchedFilename,
								result_filename
							)

	def new(self):
		dialog=NewDiffingDialog()
		dialog.setFixedSize(300,200)
		dialog.exec_()

		if len(dialog.Filenames)==0:
			return

		src_filename = str(dialog.Filenames['Orig'])
		target_filename = str(dialog.Filenames['Patched'])
		result_filename = str(dialog.Filenames['Result'])
		self.StartPerformDiff(src_filename,target_filename,result_filename)

	def StartPerformDiff(self,src_filename,target_filename,result_filename,debug=False):
		self.clearAreas()

		try:
			os.makedirs(os.path.dirname(result_filename))
		except:
			pass

		if debug:
			print 'PerformDiff: ', src_filename,target_filename,result_filename
			p=None
			PerformDiff(src_filename,target_filename,result_filename)
		else:
			p=Process(target=PerformDiff,args=(src_filename,target_filename,result_filename))
			p.start()

		if p!=None:
			while True:
				time.sleep(0.01)
				if not p.is_alive():
					break

				qApp.processEvents()
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
		self.newFromFileStoreAct = QAction("New Diffing (FileStore)...",self,shortcut=QKeySequence.New,statusTip="Create new diffing output",triggered=self.new_from_file_store)
		self.openAct = QAction("Open...",self,shortcut=QKeySequence.Open,statusTip="Open a dgf database",triggered=self.open)
		self.saveOrigGraphAct = QAction("Save orig graph...",self,shortcut=QKeySequence.Open,statusTip="Save original graph",triggered=self.saveOrigGraph)
		self.savePatchedGraphAct = QAction("Save patched graph...",self,shortcut=QKeySequence.Open,statusTip="Save patched graph",triggered=self.savePatchedGraph)

	def createMenus(self):
		self.fileMenu = self.menuBar().addMenu("&File")
		self.fileMenu.addAction(self.newAct)
		self.fileMenu.addAction(self.newFromFileStoreAct)
		self.fileMenu.addAction(self.openAct)
		self.fileMenu.addAction(self.saveOrigGraphAct)
		self.fileMenu.addAction(self.savePatchedGraphAct)

	def OpenDatabase(self,databasename):
		self.DatabaseName=databasename
		self.functions_match_table_model=FunctionMatchTable(self,self.DatabaseName)
		self.functions_match_table_view.setModel(self.functions_match_table_model)
		selection=self.functions_match_table_view.selectionModel()
		selection.selectionChanged.connect(self.handleFunctionMatchTableChanged)

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
				selection.selectionChanged.connect(self.handleBlockTableChanged)

				# Draw graphs
				self.OrigFunctionGraph.SetDatabaseName(self.DatabaseName)
				self.OrigFunctionGraph.DrawFunctionGraph("Source", source_function_address, source_match_info)
				self.OrigFunctionGraph.SetSelectBlockCallback(self.SelectedBlock)
				self.PatchedFunctionGraph.SetDatabaseName(self.DatabaseName)
				self.PatchedFunctionGraph.DrawFunctionGraph("Target", target_function_address, target_match_info)
				self.PatchedFunctionGraph.SetSelectBlockCallback(self.SelectedBlock)

				break

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

	def closeEvent(self, event):
		settings = QSettings("DarunGrim LLC", "DarunGrim")
		settings.setValue("geometry", self.saveGeometry())
		settings.setValue("geometry/functions_match_table_view", self.functions_match_table_view.saveGeometry())
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
