import sys
sys.path.append(r"\mat\Projects\ResearchTools\Graphics\PyQTGraphViz\Src")
sys.path.append(r"UI")
sys.path.append(r"..\bin")
from PyQt4.QtCore import QLocale,QTranslator
from PyQt4.QtGui import QApplication
from PyQt4.QtCore import *
from PyQt4.QtGui import *
from PyQt4.QtNetwork import *
from UI_BinaryDifferMain import Ui_MainWindow
import random
import GraphVizProcessor
import PyQTGraphDrawer
import DiffEngine
import os
import popen2 
import threading

FUNCTION_BLOCK=1

class IDAThread(threading.Thread):
	def SetCommandLine(self,command_line):
		self.command_line=command_line
	def run(self):
		import win32pipe
		print 'Executing',self.command_line
		(stdin,stdout)=win32pipe.popen4(self.command_line,"t")
		print 'End of Command'

def MakeName(i):
	return "Element:"+str(i)

CALL=0
CREF_FROM=1
CREF_TO=2
DREF_FROM=3
DREF_TO=4
def GenerateRandomMap():
	random.seed()
	map={}
	contents={}
	NumOfElement=50
	NumOfLines=NumOfElement*2
	for i in range(0,NumOfElement,1):
		contents[MakeName(i)]="""AACAAABBBB """
		map[MakeName(i)]=[]
	for i in range(0,NumOfLines,1):
		src=random.randint(0,NumOfElement-1)
		dst=random.randint(0,NumOfElement-1)
		map[MakeName(src)].append(MakeName(dst))
	return [contents,map]

class TestWindowForm(QMainWindow,Ui_MainWindow):
	def __init__(self,parent=None):
		QMainWindow.__init__(self,parent)
		self.setupUi(self)
		self.IDAClientManager=DiffEngine.IDAClientManager(1216)

	def DrawGraph(self,graphicsView,map,contents):
		scene=QGraphicsScene()
		graphicsView.setScene(scene)
		drawer=PyQTGraphDrawer.Drawer()
		graphicsView.update()
			
		########################## Drawing Test Data ##########################
		graphviz_parser=GraphVizProcessor.GraphVizParser()
		[self.NodeAttrsMap,self.EdgeAttrsMap]=graphviz_parser.GetGVData(contents,map,debug=0)
		[self.Width,self.Height]=graphviz_parser.GetRect()

		scene.setSceneRect(QRectF(-40,-40,self.Width+80,self.Height+80))
		drawer.SetRect(self.Width,self.Height)
		drawer.DrawOnScene(scene,graphviz_parser.GetNodeAttrsMap(),graphviz_parser.GetEdgeAttrsMap())
		return scene

	def OpenIDBFile(self):
		qfiledialog=QFileDialog(self)
		qfiledialog.setFilter("*.idb")
		filename=str(qfiledialog.getOpenFileName())
		if filename:
			command_line='"c:\Program Files\IDA\idag.exe" -A -SRunBinaryDiffer.idc '+filename
			ida_thread=IDAThread()
			ida_thread.SetCommandLine(command_line)
			ida_thread.start()

	@pyqtSignature("")
	def on_actionOpen_IDB_For_UnPatched_Binary_triggered(self):
		self.OpenIDBFile()
		self.IDAClientManager.CreateOneIDAClientManager(0)

	@pyqtSignature("")
	def on_actionOpen_IDB_For_Patched_Binary_triggered(self):
		self.OpenIDBFile()
		self.IDAClientManager.CreateOneIDAClientManager(1)

	@pyqtSignature("")
	def on_actionStart_Diffing_triggered(self):
		self.OneIDAClientManagers=[]
		self.OneIDAClientManagers.append(self.IDAClientManager.CreateOneIDAClientManager(0))
		self.OneIDAClientManagers.append(self.IDAClientManager.CreateOneIDAClientManager(1))
		self.DiffMachine=self.IDAClientManager.InitializeDiffMachine()
		self.DiffMachine.Analyze()
		match_info_size=self.DiffMachine.GetMatchInfoSize()
		self.Item2MatchInfo={}
		for i in range(0,match_info_size):
			match_info=self.DiffMachine.GetMatchInfo(i)
			if match_info.block_type==FUNCTION_BLOCK:
				#print match_info.addr-match_info.match_addr
				#match_info.end_addr
				#match_info.block_type
				#match_info.match_rate
				#match_info.name
				#match_info.type
				#match_info.match_name,match_info.first_found_match,match_info.first_not_found_match,match_info.second_found_match,match_info.second_not_found_match,
				item=QTreeWidgetItem(self.treeWidget_Matches)
				item.setText(0,match_info.name)
				item.setText(1,match_info.match_name)
				self.Item2MatchInfo[item]=(match_info.addr,match_info.match_addr)
	@pyqtSignature("QTreeWidgetItem *, QTreeWidgetItem *")
	def on_treeWidget_Matches_currentItemChanged(self,current_item,previous_item):
		(addr_before,addr_after)=self.Item2MatchInfo[current_item]

		[map,contents]=self.GetMap(0,addr_before)
		self.scene_Before=self.DrawGraph(self.graphicsView_Before,map,contents)

		[map,contents]=self.GetMap(1,addr_after)
		self.scene_After=self.DrawGraph(self.graphicsView_After,map,contents)

	def GetMap(self,index,root_addr):
		Map={}
		Contents={}
		addrs=[root_addr]
		for addr in addrs:
			ret=self.OneIDAClientManagers[index].GetMappedAddresses(addr,CREF_FROM)
			if ret!=0:
				[addresses,size]=ret
				targets=[]
				for i in range(0,size):
					target=int(DiffEngine.GetDWORD(addresses,i))
					targets.append(target)
					if not Map.has_key(target):
						addrs.append(target)
				Map[addr]=targets
			Contents[addr]=self.OneIDAClientManagers[index].GetDisasmLines(addr,0)
		return [Map,Contents]

__version__ = "1.0"

if __name__ == "__main__":
	app = QApplication(sys.argv)
	window = TestWindowForm()
	window.show()
	sys.exit(app.exec_())

