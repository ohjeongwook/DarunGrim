from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *
import DarunGrimDatabase
from Graphs import *
import pprint
import FlowGrapher

class FunctionMatchTable(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name, *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.database = DarunGrimDatabase.Database(database_name)

		self.match_list=[]
		self.full_fmi_list=[]
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

		return self.match_list[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Orig", "Patched", "Match"][col]
		return None

	def sort(self,col,order):
		pass

class MyGraphicsView(QGraphicsView):
	def __init__(self,parent=None):
		QGraphicsView.__init__(self,parent)
		self.setStyleSheet("QGraphicsView { background-color: rgb(99.5%, 99.5%, 99.5%); }")
		self.setRenderHints(QPainter.Antialiasing|QPainter.SmoothPixmapTransform)
		self.setDragMode(self.ScrollHandDrag)

	def wheelEvent(self,event):
		self.setTransformationAnchor(self.AnchorUnderMouse)

		scaleFactor=1.15

		if	event.delta()>0:
			self.scale(scaleFactor,scaleFactor)
		else:
			self.scale(1.0/scaleFactor, 1.0/scaleFactor)


class MainWindow(QMainWindow):
	UseDock=False
	def __init__(self,database_name):
		super(MainWindow,self).__init__()
		self.setWindowTitle("DarunGrim 4")

		# Menu
		self.createActions()
		self.createMenus()

		#
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
		self.OrigFunctionGraph=FunctionGraphScene()
		view=MyGraphicsView(self.OrigFunctionGraph)
		view.setRenderHints(QPainter.Antialiasing)

		if self.UseDock:
			dock=QDockWidget("Orig",self)
			dock.setObjectName("Orig")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(view)
			self.addDockWidget(Qt.TopDockWidgetArea,dock)
		else:
			graph_splitter.addWidget(view)

		# Function Graph
		self.PatchedFunctionGraph=FunctionGraphScene()
		view=MyGraphicsView(self.PatchedFunctionGraph)
		view.setRenderHints(QPainter.Antialiasing)

		if self.UseDock:
			dock=QDockWidget("Patched",self)
			dock.setObjectName("Patched")
			dock.setAllowedAreas(Qt.LeftDockWidgetArea|Qt.RightDockWidgetArea)
			dock.setWidget(view)
			self.addDockWidget(Qt.TopDockWidgetArea,dock)
		else:
			graph_splitter.addWidget(view)

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

	def new(self):
		pass

	def open(self):
		dialog=QFileDialog()
		if dialog.exec_():
			self.OpenDatabase(dialog.selectedFiles()[0])
			self.OrigFunctionGraph.clear()
			self.PatchedFunctionGraph.clear()
			self.block_table_model=BlockMatchTable(self)
			self.block_table_view.setModel(self.block_table_model)

	def createActions(self):
		self.newAct = QAction("New Diffing...",self,shortcut=QKeySequence.New,statusTip="Create new diffing output",triggered=self.new)
		self.openAct = QAction("Open...",self,shortcut=QKeySequence.Open,statusTip="Open a dgf database",triggered=self.open)

	def createMenus(self):
		self.fileMenu = self.menuBar().addMenu("&File")
		self.fileMenu.addAction(self.newAct)
		self.fileMenu.addAction(self.openAct)

	def DrawFunctionGraph(self,type,function_address,graph_scene,match_info):
		database=DarunGrimDatabase.Database(self.DatabaseName)

		(source_disasms, source_links) = database.GetFunctionDisasmLines(type, function_address)
		flow_grapher=FlowGrapher.FlowGrapher()
		
		for (address,disasm) in source_disasms.items():
			if not match_info.has_key(address):
				flow_grapher.SetNodeShape("white", "red", "Verdana", "12")
			else:
				if match_info[address][1]!=100:
					flow_grapher.SetNodeShape("black", "yellow", "Verdana", "12")
				else:
					flow_grapher.SetNodeShape("black", "white", "Verdana", "12")

			name="%.8X" % address
			flow_grapher.AddNode(address, name, str(disasm))

		for (src,dsts) in source_links.items():
			for dst in dsts:
				flow_grapher.AddLink(src,dst)
		graph_scene.Draw(flow_grapher)

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
					match_list.append(["%x" % source_address, "%x" % target_address, "%d%%" % match_rate])
					source_match_info[source_address]=[target_address, match_rate]
					target_match_info[target_address]=[source_address, match_rate]

				self.block_table_model=BlockMatchTable(self)
				self.block_table_model.ShowFunctionAddresses(match_list)
				self.block_table_view.setModel(self.block_table_model)

				# Draw graphs
				self.DrawFunctionGraph("Source", source_function_address, self.OrigFunctionGraph, source_match_info)
				self.DrawFunctionGraph("Target", target_function_address, self.PatchedFunctionGraph, target_match_info)

				break

	def readSettings(self):
		settings=QSettings("DarunGrim LLC", "DarunGrim")
		
		if settings.contains("geometry"):
			self.restoreGeometry(settings.value("geometry"))
		else:
			self.resize(800,600)

		self.restoreState(settings.value("windowState"))

		"""
		if settings.contains("geometry/functions_match_table"):
			self.functions_match_table_view.restoreGeometry(settings.value("geometry/functions_match_table_view"))
		else:
			self.functions_match_table_view.resize(200,400)

		if settings.contains("geometry/block_table_view"):
			self.block_table_view.restoreGeometry(settings.value("geometry/block_table_view"))
		else:
			self.block_table_view.resize(200,400)

		
		self.functions_match_table_view.resize(200,400)
		self.block_table_view.resize(200,400)
		"""

	def closeEvent(self, event):
		settings = QSettings("DarunGrim LLC", "DarunGrim")
		settings.setValue("geometry", self.saveGeometry())
		settings.setValue("geometry/functions_match_table_view", self.functions_match_table_view.saveGeometry())
		settings.setValue("geometry/block_table_view", self.block_table_view.saveGeometry())
		settings.setValue("windowState", self.saveState())
		QMainWindow.closeEvent(self, event)

	def resizeEvent(self,event):
		print 'resizeEvent'
		"""
		self.functions_match_table_view.resize(200,400)
		self.block_table_view.resize(200,400)
		"""

if __name__=='__main__':
	import sys

	database_name=sys.argv[1]
	app=QApplication(sys.argv)
	mainWindow=MainWindow(database_name)
	mainWindow.show()
	sys.exit(app.exec_())
