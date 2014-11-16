from PySide.QtCore import *
from PySide.QtGui import *
from PySide.QtSql import *

import pprint
import os
import FileStoreDatabase
import operator

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
		return self.CompanyNames[row][0]

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
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.CompanyNames=sorted(self.CompanyNames,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.CompanyNames.reverse()
		self.emit(SIGNAL("layoutChanged()"))

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
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.Tags=sorted(self.Tags,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.Tags.reverse()
		self.emit(SIGNAL("layoutChanged()"))

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
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.FileNames=sorted(self.FileNames,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.FileNames.reverse()
		self.emit(SIGNAL("layoutChanged()"))

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
					self.FileIndexes.append([fileindex.filename, 
											fileindex.arch, 
											fileindex.company_name, 
											fileindex.version_string, 
											tag, 
											fileindex.sha1,
											fileindex.id,
											fileindex.full_path ])
			elif tag:
				for (fileindex,tags) in database.GetFilesByTag(tag):
					self.FileIndexes.append([fileindex.filename, 
											fileindex.arch, 
											fileindex.company_name, 
											fileindex.version_string, 
											tag, 
											fileindex.sha1,
											fileindex.id,
											fileindex.full_path ])

	def GetFilename(self,row):
		return self.FileIndexes[row][7]

	def GetFileIndex(self,row):
		return self.FileIndexes[row]

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
		self.emit(SIGNAL("layoutAboutToBeChanged()"))
		self.FileIndexes=sorted(self.FileIndexes,key=operator.itemgetter(col))
		if order==Qt.DescendingOrder:
			self.FileIndexes.reverse()
		self.emit(SIGNAL("layoutChanged()"))

class VersionsTableModel(QAbstractTableModel):
	Debug=0
	def __init__(self,parent, database_name='', company_name='', filename='', *args):
		QAbstractTableModel.__init__(self,parent,*args)
		self.Versions=[]

		if database_name:
			database=FileStoreDatabase.Database(database_name)
			for fileindex in database.GetFilesByCompanyFilename(company_name,filename):
				self.Versions.append((fileindex.version_string,fileindex.sha1,fileindex.id, fileindex.full_path))
			del database

	def GetFilename(self,row):
		return self.Versions[row][3]

	def GetVersion(self,row):
		return self.Versions[row]

	def GetName(self,row):
		return str(self.Versions[row][0])

	def rowCount(self,parent):
		return len(self.Versions)
	
	def columnCount(self,parent):
		return 2

	def data(self,index,role):
		if not index.isValid():
			return None
		elif role!=Qt.DisplayRole:
			return None

		return self.Versions[index.row()][index.column()]

	def headerData(self,col,orientation,role):
		if orientation==Qt.Horizontal and role==Qt.DisplayRole:
			return ["Versions","SHA1"][col]
		return None

	def sort(self,col,order):
		pass

class ImportMSUDialog(QDialog):
	def __init__(self,parent=None):
		super(ImportMSUDialog,self).__init__(parent)

		self.Filename=''

		file_button=QPushButton('Orig File:',self)
		file_button.clicked.connect(self.getFilename)
		self.file_line=QLineEdit("")
		self.file_line.setAlignment(Qt.AlignLeft)

		tag_button=QLabel('Tag:',self)
		self.tag_line=QLineEdit("")
		self.tag_line.setAlignment(Qt.AlignLeft)

		buttonBox = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
		buttonBox.accepted.connect(self.accept)
		buttonBox.rejected.connect(self.reject)

		main_layout=QGridLayout()
		main_layout.addWidget(file_button,0,0)
		main_layout.addWidget(self.file_line,0,1)
		main_layout.addWidget(tag_button,1,0)
		main_layout.addWidget(self.tag_line,1,1)
		main_layout.addWidget(buttonBox,2,1)
		self.setLayout(main_layout)

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(ImportMSUDialog,self).keyPressEvent(e)

	def getTags(self):
		return self.tag_line.text()

	def getFilename(self):
		dialog=QFileDialog()
		dialog.setNameFilter("MSU Files (*.msu)")
		filename=''
		if dialog.exec_():
			self.Filename=dialog.selectedFiles()[0]

		self.file_line.setText(self.Filename)

class FilesWidgetsTemplate:
	def __init__(self,parent,database_name):
		self.DatabaseName=database_name
		self.DarunGrimStore = "Z:\\DarunGrimStore" #TOOD:
		self.parent=parent
		vert_splitter=QSplitter()
		# Company
		view=QTableView()
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		vert_splitter.addWidget(view)
		self.CompanyNamesTable=view

		self.CompanyNames=CompanyNamesTableModel(parent,self.DatabaseName)
		self.CompanyNamesTable.setModel(self.CompanyNames)
		selection=self.CompanyNamesTable.selectionModel()
		if selection!=None:
			selection.selectionChanged.connect(self.handleCompanyNamesTableChanged)

		# File
		view=QTableView()
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		vert_splitter.addWidget(view)
		self.FileNamesTable=view

		# Version
		view=QTableView()
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		vert_splitter.addWidget(view)
		self.VersionsTable=view

		search_tab_vert_splitter=QSplitter()
		search_tab_vert_splitter.setStretchFactor(0,0)
		search_tab_vert_splitter.setStretchFactor(1,1)

		#Search pane
		search_pane_splitter=QSplitter()
		search_pane_splitter.setOrientation(Qt.Vertical)

		# Tags
		view=QTableView()
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		search_pane_splitter.addWidget(view)
		self.TagsTable=view

		self.Tags=TagsTableModel(parent,self.DatabaseName)
		self.TagsTable.setModel(self.Tags)
		selection=self.TagsTable.selectionModel()
		if selection!=None:
			selection.selectionChanged.connect(self.handleTagsTableChanged)

		#Search box
		self.search_line=QLineEdit()
		self.search_line.setAlignment(Qt.AlignLeft)
		self.search_line.editingFinished.connect(self.searchLineFinished)

		search_button=QPushButton('Search',parent)
		search_button.clicked.connect(self.SearchName)

		search_widget=QWidget()
		hlayout=QHBoxLayout()
		hlayout.addWidget(self.search_line)
		hlayout.addWidget(search_button)
		search_widget.setLayout(hlayout)

		search_pane_splitter.addWidget(search_widget)
		
		button_box=QDialogButtonBox()

		import_msu_button=button_box.addButton("Import MSU", QDialogButtonBox.ActionRole)
		import_msu_button.clicked.connect(self.importMSU)
		search_pane_splitter.addWidget(button_box)

		search_tab_vert_splitter.addWidget(search_pane_splitter)
		
					
		# File
		view=QTableView()
		view.horizontalHeader().setResizeMode(QHeaderView.Stretch)
		view.setSortingEnabled(True)
		view.setSelectionBehavior(QAbstractItemView.SelectRows)

		vheader=QHeaderView(Qt.Orientation.Vertical)
		vheader.setResizeMode(QHeaderView.ResizeToContents)
		view.setVerticalHeader(vheader)

		search_tab_vert_splitter.addWidget(view)
		self.FileIndexTable=view

		search_tab_vert_splitter.setStretchFactor(0,0)
		search_tab_vert_splitter.setStretchFactor(1,1)

		# Layout
		vert_splitter.setStretchFactor(0,0)
		vert_splitter.setStretchFactor(1,1)

		browe_files_tab_widget=QWidget()
		vlayout=QVBoxLayout()
		vlayout.addWidget(vert_splitter)
		browe_files_tab_widget.setLayout(vlayout)

		search_files_tab_widget=QWidget()
		vlayout=QVBoxLayout()
		vlayout.addWidget(search_tab_vert_splitter)
		search_files_tab_widget.setLayout(vlayout)

		self.tab_widget=QTabWidget()
		self.tab_widget.addTab(browe_files_tab_widget,"Browse Files...")
		self.tab_widget.addTab(search_files_tab_widget,"Search Files...")

	def keyPressEvent(self,e):
		key=e.key()

		if key==Qt.Key_Return or key==Qt.Key_Enter:
			return
		else:
			super(FilesWidgetsTemplate,self).keyPressEvent(e)

	def setDarunGrimStore(self,darungrim_store):
		self.DarunGrimStore=darungrim_store

	def importMSU(self):
		dialog=ImportMSUDialog()
		if dialog.exec_():
			filename=dialog.Filename
			tags=dialog.getTags().split(',')

			if len(tags)==0 or (len(tags)==1 and tags[0]==''):
				tags=[os.path.basename(filename)]				

			import FileStore
			import MSPatchFile
			file_store = FileStore.FileProcessor( databasename = r'index.db' )

			ms_patch_handler=MSPatchFile.MSPatchHandler()

			for src_dirname in ms_patch_handler.Extract(filename):
				print 'Store: %s -> %s (tags:%s)' % (src_dirname, self.DarunGrimStore, ','.join(tags))
				file_store.CheckInFiles( src_dirname, target_dirname = self.DarunGrimStore, tags=tags )

	def handleCompanyNamesTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				self.CompanyName=self.CompanyNames.GetName(index.row())

				self.FileNames=FileNamesTableModel(self.parent,self.DatabaseName,self.CompanyName)
				self.FileNamesTable.setModel(self.FileNames)

				selection=self.FileNamesTable.selectionModel()
				if selection!=None:
					selection.selectionChanged.connect(self.handleFileNamesTableChanged)

				self.Versions=VersionsTableModel(self.parent)
				self.VersionsTable.setModel(self.Versions)

				break

	def handleFileNamesTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				file_name=self.FileNames.GetName(index.row())
				self.Versions=VersionsTableModel(self.parent,self.DatabaseName,self.CompanyName,file_name)
				self.VersionsTable.setModel(self.Versions)

	def handleTagsTableChanged(self,selected,dselected):
		for item in selected:
			for index in item.indexes():
				tag=self.Tags.GetName(index.row())

				self.FileIndexes=FileIndexTableModel(self.parent,self.DatabaseName,tag=tag)
				self.FileIndexTable.setModel(self.FileIndexes)
				break
				
	def searchLineFinished(self):
		self.SearchName()

	def SearchName(self):
		name=self.search_line.text()
		self.FileIndexes=FileIndexTableModel(self.parent,self.DatabaseName,name=name)
		self.FileIndexTable.setModel(self.FileIndexes)

	def getCurrentSelection(self):
		tab_selection=self.tab_widget.currentIndex()
		if tab_selection==0:
			selection=self.VersionsTable.selectionModel()
			if selection!=None:
				for index in selection.selection().indexes():
					version_info=self.Versions.GetVersion(index.row())
					return {'id': version_info[2], 'filename': version_info[3], 'sha1': version_info[1]}
		else:
			selection=self.FileIndexTable.selectionModel()
			if selection!=None:
				for index in selection.selection().indexes():
					file_index=self.FileIndexes.GetFileIndex(index.row())
					return {'id': file_index[6], 'filename': file_index[7], 'sha1': file_index[5]}
		return None

if __name__=='__main__':
	class MainWindow(QMainWindow):
		def __init__(self,database_name):
			super(MainWindow,self).__init__()
			self.DatabaseName=database_name

			self.setWindowTitle("FileStore Browser")

			self.createActions()
			self.createMenus()

			self.filesWidgetsTemplate=FilesWidgetsTemplate(self,database_name)

			self.central_widget=QWidget()
			vlayout=QVBoxLayout()
			vlayout.addWidget(self.filesWidgetsTemplate.tab_widget)
			self.central_widget.setLayout(vlayout)
			self.setCentralWidget(self.central_widget)
			self.show()

			self.readSettings()

		def clearAreas(self):
			self.CompanyNames=CompanyNamesTableModel(self)
			self.CompanyNamesTable.setModel(self.CompanyNames)

		def importFiles(self):
			pass

		def importMSUFiles(self):
			dialog=ImportMSUDialog()
			if dialog.exec_():
				filename=dialog.Filename
				tags=dialog.getTags.split(',')

				if len(tags)==0 or (len(tags)==1 and tags[0]==''):
					tags=[os.path.basename(filename)]				

				import FileStore
				import MSPatchFile
				file_store = FileStore.FileProcessor( databasename = r'index.db' )

				ms_patch_handler=MSPatchFile.MSPatchHandler()

				for src_dirname in ms_patch_handler.Extract(filename):
					print 'Store: %s -> %s (tags:%s)' % (src_dirname, self.DarunGrimStore, ','.join(tags))
					file_store.CheckInFiles( src_dirname, target_dirname = self.DarunGrimStore, tags=tags )

		def createActions(self):
			self.ImportAct = QAction("Import files...",self,shortcut=QKeySequence.New,statusTip="Import file",triggered=self.importFiles)
			self.ImportMSUAct = QAction("Import MSU files...",self,statusTip="Import file",triggered=self.importMSUFiles)

		def createMenus(self):
			self.fileMenu = self.menuBar().addMenu("&File")
			self.fileMenu.addAction(self.ImportAct)
			self.fileMenu.addAction(self.ImportMSUAct)


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

	import sys

	if len(sys.argv)>1:
		database_name=sys.argv[1]
	else:
		database_name='index.db'

	app=QApplication(sys.argv)
	mainWindow=MainWindow(database_name)
	mainWindow.show()
	sys.exit(app.exec_())
