from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *

import pprint
import os
import FileStoreDatabase

class CompanyNamesTableModel(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.CompanyNames=[]

		if database_name:
			database=FileStoreDatabase.Database(database_name)
			for company_name in database.GetCompanyNames():
				self.CompanyNames.append((company_name,))

	def GetName(self,row):
		return str(self.CompanyNames[row][0])

	def rowCount(self,parent):
		return len(self.CompanyNames)
	
	def columnCount(self,parent):
		return 1

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.CompanyNames[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name",][col]
		return None

	def sort(self,col,order):
		pass

class TagsTableModel(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.Tags=[]

		if database_name:
			database=FileStoreDatabase.Database(database_name)
			for tag in database.GetTags():
				self.Tags.append((tag,))

	def GetName(self,row):
		return str(self.Tags[row][0])

	def rowCount(self,parent):
		return len(self.Tags)
	
	def columnCount(self,parent):
		return 1

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.Tags[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name",][col]
		return None

	def sort(self,col,order):
		pass

class FileNamesTableModel(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', company_name='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.FileNames=[]

		if database_name:
			database=FileStoreDatabase.Database(database_name)
			for file in database.GetFilesByCompanyName(company_name):
				self.FileNames.append((file.filename,file.arch))

	def GetName(self,row):
		return str(self.FileNames[row][0])

	def rowCount(self,parent):
		return len(self.FileNames)
	
	def columnCount(self,parent):
		return 2

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.FileNames[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name","Arch"][col]
		return None

	def sort(self,col,order):
		pass

class FileIndexTableModel(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', name='', tag='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.FileIndexes=[]

		if database_name:
			database=FileStoreDatabase.Database(database_name)
			if name:
				for (fileindex,tags) in database.SearchFiles(name):
					tag=''
					if tags!=None:
						tag=tags.tag
					self.FileIndexes.append([fileindex.filename, ret.arch, fileindex.company_name, fileindex.version_string, tag, fileindex.sha1 ])

			elif tag:
				for (ret,tags) in database.GetFilesByTag(tag):
					self.FileIndexes.append([ret.filename, ret.arch, ret.company_name, ret.version_string, tag, ret.sha1 ])

	def GetName(self,row):
		return str(self.FileIndexes[row][0])

	def rowCount(self,parent):
		return len(self.FileIndexes)
	
	def columnCount(self,parent):
		return 6

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.FileIndexes[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Name","Arch","Company","Version","Tag","SHA1"][col]
		return None

	def sort(self,col,order):
		pass

class VersionsTableModel(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', company_name='', filename='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.Versions=[]

		if database_name:
			database=FileStoreDatabase.Database(database_name)
			for version in database.GetVersionStrings(company_name,filename):
				self.Versions.append((version,))
			del database

	def GetName(self,row):
		return str(self.Versions[row][0])

	def rowCount(self,parent):
		return len(self.Versions)
	
	def columnCount(self,parent):
		return 1

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.Versions[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Versions",][col]
		return None

	def sort(self,col,order):
		pass

class MainWindow(QMainWindow):
	def __init__(self,database_name):
		super(MainWindow,self).__init__()
		self.setWindowTitle("FileStore Browser")

		self.DatabaseName=database_name

		vert_splitter=QSplitter()
		# Company
		view=QTableView()
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)
		vert_splitter.addWidget(view)
		self.CompanyNamesTable=view

		self.CompanyNames=CompanyNamesTableModel(self,self.DatabaseName)
		self.CompanyNamesTable.setModel(self.CompanyNames)
		selection=self.CompanyNamesTable.selectionModel()
		selection.selectionChanged.connect(self.handleCompanyNamesTableChanged)

		# File
		view=QTableView()
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)
		vert_splitter.addWidget(view)
		self.FileNamesTable=view

		# Version
		view=QTableView()
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)
		vert_splitter.addWidget(view)
		self.VersionsTable=view
		#selection=self.VersionsTable.selectionModel()
		#selection.selectionChanged.connect(self.handleFileNamesTableChanged)

		search_tab_vert_splitter=QSplitter()

		#Search pane
		search_pane_splitter=QSplitter()
		search_pane_splitter.setOrientation(Qt.Vertical)

		# Tags
		view=QTableView()
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)
		search_pane_splitter.addWidget(view)
		self.TagsTable=view

		self.Tags=TagsTableModel(self,self.DatabaseName)
		self.TagsTable.setModel(self.Tags)
		selection=self.TagsTable.selectionModel()
		selection.selectionChanged.connect(self.handleTagsTableChanged)

		#Search box
		self.search_line=QLineEdit()
		self.search_line.editingFinished.connect(self.searchLineFinished)

		search_button=QPushButton('Search',self)
		search_button.clicked.connect(self.SearchName)

		search_widget=QWidget()
		hlayout=QHBoxLayout()
		hlayout.addWidget(self.search_line)
		hlayout.addWidget(search_button)
		search_widget.setLayout(hlayout)
		search_pane_splitter.addWidget(search_widget)
		
		search_tab_vert_splitter.addWidget(search_pane_splitter)

		# File
		view=QTableView()
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		hheader=QHeaderView(Qt.Orientation.Horizontal)
		hheader.setResizeMode(QHeaderView.Stretch)
		view.setHorizontalHeader(hheader)
		search_tab_vert_splitter.addWidget(view)
		self.FileIndexTable=view

		# Layout
		browe_files_tab_widget=QWidget()
		vlayout=QVBoxLayout()
		vlayout.addWidget(vert_splitter)
		browe_files_tab_widget.setLayout(vlayout)

		search_files_tab_widget=QWidget()
		vlayout=QVBoxLayout()
		vlayout.addWidget(search_tab_vert_splitter)
		search_files_tab_widget.setLayout(vlayout)

		tab_widget=QTabWidget()
		tab_widget.addTab(browe_files_tab_widget,"Browse Files...")
		tab_widget.addTab(search_files_tab_widget,"Search Files...")

		central_widget=QWidget()
		vlayout=QVBoxLayout()
		vlayout.addWidget(tab_widget)
		central_widget.setLayout(vlayout)

		self.setCentralWidget(central_widget)
		self.show()

		self.readSettings()

	def handleCompanyNamesTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				self.CompanyName=self.CompanyNames.GetName(index.row())

				self.FileNames=FileNamesTableModel(self,self.DatabaseName,self.CompanyName)
				self.FileNamesTable.setModel(self.FileNames)

				selection=self.FileNamesTable.selectionModel()
				selection.selectionChanged.connect(self.handleFileNamesTableChanged)

				self.Versions=VersionsTableModel(self)
				self.VersionsTable.setModel(self.Versions)

				break

	def handleFileNamesTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				file_name=self.FileNames.GetName(index.row())
				print self.CompanyName, file_name
				self.Versions=VersionsTableModel(self,self.DatabaseName,self.CompanyName,file_name)
				self.VersionsTable.setModel(self.Versions)

	def handleTagsTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				tag=self.Tags.GetName(index.row())

				self.FileIndexes=FileIndexTableModel(self,self.DatabaseName,tag=tag)
				self.FileIndexTable.setModel(self.FileIndexes)
				break
				
	def searchLineFinished(self):
		name=self.search_line.text()
		self.FileIndexes=FileIndexTableModel(self,self.DatabaseName,name=name)
		self.FileIndexTable.setModel(self.FileIndexes)

	def SearchName(self):
		name=self.search_line.text()
		self.FileIndexes=FileIndexTableModel(self,self.DatabaseName,name=name)
		self.FileIndexTable.setModel(self.FileIndexes)

	def clearAreas(self):
		self.CompanyNames=CompanyNamesTableModel(self)
		self.CompanyNamesTable.setModel(self.CompanyNames)

	def readSettings(self):
		settings=QSettings("DarunGrim LLC", "FileStoreBrowser")
		
		if settings.contains("geometry"):
			self.restoreGeometry(settings.value("geometry"))
		else:
			self.resize(800,600)

		self.restoreState(settings.value("windowState"))

	def closeEvent(self, event):
		settings = QSettings("DarunGrim LLC", "DarunGrim")
		settings.setValue("geometry", self.saveGeometry())
		settings.setValue("windowState", self.saveState())
		QMainWindow.closeEvent(self, event)

if __name__=='__main__':
	import sys

	if len(sys.argv)>1:
		database_name=sys.argv[1]
	else:
		database_name='index.db'

	app=QApplication(sys.argv)
	mainWindow=MainWindow(database_name)
	mainWindow.show()
	sys.exit(app.exec_())
