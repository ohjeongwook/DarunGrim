#!/usr/bin/env python
import sys
sys.path.append(r'\mat\Projects\ResearchTools\Graphics\GraphVizInterface\Python')
sys.path.append(r"..\bin")
import pygtk
pygtk.require('2.0')
import gtk
import gtk,gobject,cairo
import operator
import time
import string
import zipfile
import os

import GraphVizProcessor
import Drawer
import threading
import thread
import DiffEngine
import gc

FUNCTION_BLOCK=1
CALL=0
CREF_FROM=1
CREF_TO=2
DREF_FROM=3
DREF_TO=4

class IDAThread(threading.Thread):
	def SetCommandLine(self,command_line):
		self.command_line=command_line
	def run(self):
		import win32pipe
		print 'Executing',self.command_line
		(stdin,stdout)=win32pipe.popen4(self.command_line,"t")
		print 'End of Command'

class DiffBrowser:
	def __init__(self):
		self.FileName=None
		self.DoSyncWithIDA=True
		self.DiffingThread=None
		self.AreaInformations={}
		######################################################
		self.window=gtk.Window(gtk.WINDOW_TOPLEVEL)
		self.window.set_title("Binary Differ")
		self.window.set_size_request(800,600)
		self.window.connect("destroy",self.gtk_destory)

		vbox=gtk.VBox(False,0)
		self.window.add(vbox)
		vbox.show()
	
		######################################################
		ui_manager=gtk.UIManager()
		accel_group=ui_manager.get_accel_group()
		self.window.add_accel_group(accel_group)
		action_group=gtk.ActionGroup('Simple_GTK Actiongroup')
		# Create Actions
		action_group.add_actions(
			[
				("File",None,"File","F",None,None),
				 ("Open File",None,"Open File","O",None,self.OpenFile),
				 ("Start IDA Diff Session",None,"Start IDA Diff Session","I",None,self.StartIDADiffSession),
				 ("Save",None,"Save","S",None,self.SaveFile),
				 ("Save As",None,"Save As","A",None,self.SaveAsFile),
				 ("Quit",None,"Quit","Q",None,self.OnQuit)
			]
		)  
		ui_manager.insert_action_group(action_group,0)
		ui='''<ui>
		<menubar name="MenuBar">
		  <menu action="File">
			<menuitem action="Open File"/>
			<menuitem action="Start IDA Diff Session"/>
			<menuitem action="Save"/>
			<menuitem action="Save As"/>
			<menuitem action="Quit"/>
		  </menu>
		</menubar>
		</ui>'''
		ui_manager.add_ui_from_string(ui)
		menubar=ui_manager.get_widget('/MenuBar')
		vbox.pack_start(menubar,False,False,2)
		menubar.show()
		######################################################
		self.area=[]
		self.area.append(gtk.DrawingArea())
		self.area[0].set_size_request(100,100)
		self.pangolayout=self.area[0].create_pango_layout("")
		self.sw=[]
		self.sw.append(gtk.ScrolledWindow())
		self.sw[0].add_with_viewport(self.area[0])

		self.area[0].set_events(gtk.gdk.EXPOSURE_MASK|gtk.gdk.BUTTON_PRESS_MASK)
		self.area[0].connect("configure-event",self.area_configure)
		self.area[0].connect("expose-event",self.area_expose)
		self.area[0].connect("button-press-event", self.area_button_press)

		self.hpaned=gtk.HPaned()
		self.hpaned.add1(self.sw[0])
		self.hadj=self.sw[0].get_hadjustment()
		self.vadj=self.sw[0].get_vadjustment()
		######################################################
		self.area.append(gtk.DrawingArea())
		self.area[1].set_size_request(100,100)
		self.pangolayout2=self.area[1].create_pango_layout("")
		self.sw.append(gtk.ScrolledWindow())
		self.sw[1].add_with_viewport(self.area[1])
		self.hpaned.add2(self.sw[1])

		self.area[1].set_events(gtk.gdk.EXPOSURE_MASK|gtk.gdk.BUTTON_PRESS_MASK) 
		self.area[1].connect("configure-event",self.area_configure)
		self.area[1].connect("expose-event",self.area_expose)
		self.area[1].connect("button-press-event", self.area_button_press)
		self.hadj2=self.sw[1].get_hadjustment()
		self.vadj2=self.sw[1].get_vadjustment()
		######################################################
		self.tvw_diff_list=gtk.TreeView()

		##########
		cell=gtk.CellRendererText()
		
		tvcolumn=gtk.TreeViewColumn('Before')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',0)
		tvcolumn.set_sort_column_id(0)

		"""
		tvcolumn=gtk.TreeViewColumn('Address')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',1)
		tvcolumn.set_sort_column_id(1)

		tvcolumn=gtk.TreeViewColumn('Matched Blocks')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',2)
		tvcolumn.set_sort_column_id(2)
		"""

		tvcolumn=gtk.TreeViewColumn('Unmatched')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',3)
		tvcolumn.set_sort_column_id(3)
		
		tvcolumn=gtk.TreeViewColumn('After')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',4)
		tvcolumn.set_sort_column_id(4)

		"""
		tvcolumn=gtk.TreeViewColumn('Address')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',5)
		tvcolumn.set_sort_column_id(5)
		"""


		tvcolumn=gtk.TreeViewColumn('Unmatched')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',7)
		tvcolumn.set_sort_column_id(7)

		tvcolumn=gtk.TreeViewColumn('Different')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',8)
		tvcolumn.set_sort_column_id(8)

		tvcolumn=gtk.TreeViewColumn('Matched')
		self.tvw_diff_list.append_column(tvcolumn)
		tvcolumn.pack_start(cell,True)
		tvcolumn.set_resizable(True)
		tvcolumn.add_attribute(cell,'text',2)
		tvcolumn.set_sort_column_id(2)
		##########

		self.tvw_diff_list.set_search_column(0)
		self.tvw_diff_list.set_search_column(0)
		self.tvw_diff_list.set_reorderable(True)

		self.vpaned=gtk.VPaned()
		self.vpaned.add1(self.hpaned)
		self.sw_tvw_diff_list=gtk.ScrolledWindow()
		self.sw_tvw_diff_list.add_with_viewport(self.tvw_diff_list)
		self.vpaned.add2(self.sw_tvw_diff_list)
		self.sw_tvw_diff_list.show()

		self.tvw_diff_list.connect("row-activated",self.tvw_diff_list_row_activated)
		self.tvw_diff_list.show()

		self.previous_width=-1
		self.previous_height=-1
		self.window.connect("size-allocate",self.window_size_allocate)
		(width,height)=self.window.get_size_request()
		self.hpaned.set_position(width/2)
		self.vpaned.set_position(height*0.6)

		vbox.pack_end(self.vpaned,True,True,2)
		self.area[0].show()
		self.sw[0].show()
		self.area[1].show()
		self.sw[1].show()
		self.hpaned.show()
		self.vpaned.show()
		self.window.show()

    	def OpenFile(self,widget=None,event=None,data=None):
		dialog=gtk.FileChooserDialog("Open..",
				None,
				gtk.FILE_CHOOSER_ACTION_OPEN,
				(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_OPEN,gtk.RESPONSE_OK))
		
		dialog.set_default_response(gtk.RESPONSE_OK)
		
		filter=gtk.FileFilter()
		filter.set_name("Diff Files")
		filter.add_pattern("*.bdf")
		dialog.add_filter(filter)
		
		response=dialog.run()
		if response == gtk.RESPONSE_OK:
			self.FileName=dialog.get_filename()
			self.StartDiffing(self.FileName)
		elif response == gtk.RESPONSE_CANCEL:
			print 'Closed, no files selected'
		dialog.destroy()

    	def SaveAsFile(self,widget=None,event=None,data=None):
		self.SaveToFile()

    	def SaveFile(self,widget=None,event=None,data=None):
		self.SaveToFile(self.FileName)

	def SaveToFile(self,filename=None):
		if not filename:
			dialog=gtk.FileChooserDialog("Save..",
					None,
					gtk.FILE_CHOOSER_ACTION_SAVE,
					(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_OPEN,gtk.RESPONSE_OK))
			
			dialog.set_default_response(gtk.RESPONSE_OK)
			
			filter=gtk.FileFilter()
			filter.set_name("Diff Files")
			filter.add_pattern("*.bdf")
			dialog.add_filter(filter)
			
			response=dialog.run()
			if response == gtk.RESPONSE_OK:
				filename=dialog.get_filename()
				if filename.find(".bdf")<0:
					filename+=".bdf"
				self.FileName=filename
			dialog.destroy()

		if filename:
			self.OneClientManagerBefore.Save("before.data")
			self.OneClientManagerAfter.Save("after.data")
			self.DiffMachine.Save("result.data")
			file=zipfile.ZipFile(filename, "w")
			for name in ("before.data","after.data","result.data"):
				file.write(name,os.path.basename(name), zipfile.ZIP_DEFLATED)
			os.unlink("before.data")
			os.unlink("after.data")
			os.unlink("result.data")
			file.close()

	def OnQuit(self,widget=None,event=None,data=None):
		pass

	def StartIDADiffSession(self,widget=None,event=None,data=None):
		self.DiffingThread=threading.Thread(target=self.StartDiffing).start()

	def window_size_allocate(self,widget,allocation):
		if self.previous_width!=allocation.width or self.previous_height!=allocation.height:
			if self.previous_width!=-1 and self.previous_height!=-1:
				self.hpaned.set_position(allocation.width*self.hpaned.get_position()/self.previous_width)
				self.vpaned.set_position(allocation.height*self.vpaned.get_position()/self.previous_height)

			self.previous_width=allocation.width
			self.previous_height=allocation.height

	def area_configure(self,widget,event):
		if self.AreaInformations.has_key(widget):
			self.CenterAddr(self.AreaInformations[widget][2],self.AreaInformations[widget][3])

	def area_expose(self,widget,event):
		if self.AreaInformations.has_key(widget):
			widget.window.draw_drawable(
				widget.get_style().fg_gc[gtk.STATE_NORMAL],
				self.AreaInformations[widget][0],
				event.area.x,event.area.y,
				event.area.x,event.area.y,
				event.area.width,event.area.height)
			

	def tvw_diff_list_row_activated(self,widget,path,view_column):
		iter=self.treestore.get_iter(path)
		(addr,match_addr)=self.treestore.get(iter,1,5)

		if self.DoSyncWithIDA:
			self.OneIDAClientManagers[0].ShowAddress(addr)
			self.OneIDAClientManagers[1].ShowAddress(match_addr)

		del self.AreaInformations
		gc.collect()
		self.AreaInformations={}
		[map,contents]=self.GetMap(0,addr)
		self.AreaInformations[self.area[0]]=self.GetPixmapFromMap(map,contents)
		self.AreaInformations[self.area[0]].append(0)
		self.AreaInformations[self.area[0]].append(addr)
		[width,height]=self.AreaInformations[self.area[0]][0].get_size()
		self.area[0].set_size_request(width,height)

		[map,contents]=self.GetMap(1,match_addr)
		self.AreaInformations[self.area[1]]=self.GetPixmapFromMap(map,contents)
		self.AreaInformations[self.area[1]].append(1)
		self.AreaInformations[self.area[1]].append(match_addr)
		[width,height]=self.AreaInformations[self.area[1]][0].get_size()
		self.area[1].set_size_request(width,height)

	def GetPixmapFromMap(self,map,contents):
		drawer=Drawer.DrawerForCairo(contents,map)
		[width,height]=drawer.GetRect()
		pixmap=gtk.gdk.Pixmap(None,width,height,24)
		cr=pixmap.cairo_create()
		cr.set_source_rgb(200,200,200)
		cr.set_operator (cairo.OPERATOR_SOURCE)
		cr.paint()
		drawer.Draw(cr)
		return [pixmap,drawer]

	def area_button_press(self,widget,event):
		if self.AreaInformations.has_key(widget):
			address=self.AreaInformations[widget][1].GetRegionName(event.x,event.y)
			if address:
				index=self.AreaInformations[widget][2]
				match_address=self.DiffMachine.GetMatchAddr(index,address)
				if index==0:
					self.CenterAddr(0,address)
					self.CenterAddr(1,match_address)
					if self.DoSyncWithIDA:
						self.OneIDAClientManagers[0].ShowAddress(address)
						self.OneIDAClientManagers[1].ShowAddress(match_address)
				else:
					self.CenterAddr(1,address)
					self.CenterAddr(0,match_address)
					if self.DoSyncWithIDA:
						self.OneIDAClientManagers[1].ShowAddress(address)
						self.OneIDAClientManagers[0].ShowAddress(match_address)

	def CenterAddr(self,index,addr):
		(x,y)=self.AreaInformations[self.area[index]][1].GetRegionPosition(addr)
		if x!=0 or y!=0:
			self.CenterXY(self.sw[index],x,y)

	def CenterXY(self,sw,x,y):
		hadj=sw.get_hadjustment()
		x-=hadj.page_size/2
		if x>hadj.upper-hadj.page_size:
			x=hadj.upper-hadj.page_size
		elif x<0:
			x=0
		vadj=sw.get_vadjustment()
		y-=vadj.page_size/2
		if y>vadj.upper-vadj.page_size:
			y=vadj.upper-vadj.page_size
		elif y<0:
			y=0
		hadj.set_value(x)
		vadj.set_value(y)

	def gtk_destory(self,arg):
		gtk.main_quit()

	def CenterAddr(self,index,addr):
		(x,y)=self.AreaInformations[self.area[index]][1].GetRegionPosition(addr)
		if x!=0 or y!=0:
			self.CenterXY(self.sw[index],x,y)

	def CenterXY(self,sw,x,y):
		hadj=sw.get_hadjustment()
		x-=hadj.page_size/2
		if x>hadj.upper-hadj.page_size:
			x=hadj.upper-hadj.page_size
		elif x<0:
			x=0
		vadj=sw.get_vadjustment()
		y-=vadj.page_size/2
		if y>vadj.upper-vadj.page_size:
			y=vadj.upper-vadj.page_size
		elif y<0:
			y=0
		hadj.set_value(x)
		vadj.set_value(y)

	def gtk_destory(self,arg):
		gtk.main_quit()
		if self.DiffingThread:
			del self.DiffingThread
		sys.exit()

	def __del__(self):
		print 'End of operation'
		if self.DiffingThread:
			pass

	def StartDiffing(self,filename=None):
		self.OneIDAClientManagers=[]
		DoSyncWithIDA=self.DoSyncWithIDA
		if filename:
			print 'Retrieving',filename
			self.Mode='retrieve'
			DoSyncWithIDA=False
		else:
			self.IDAClientManager=DiffEngine.IDAClientManager(1216)
			self.Mode='save'
		if self.Mode=='retrieve':
			tmp_path="tmp"
			file=zipfile.ZipFile(filename, "r")
			try:
				os.makedirs(tmp_path)
			except:
				pass
	
			before_filename=os.path.join(tmp_path,"before.dat")
			fd=open(before_filename,"wb")
			data=file.read("before.data")
			fd.write(data)
			fd.close()
	
			after_filename=os.path.join(tmp_path,"after.dat")
			fd=open(after_filename,"wb")
			data=file.read("after.data")
			fd.write(data)
			fd.close()
	
			result_filename=os.path.join(tmp_path,"result.dat")
			fd=open(result_filename,"wb")
			data=file.read("result.data")
			fd.write(data)
			fd.close()

		if self.Mode=='retrieve':
			self.OneClientManagerBefore=DiffEngine.OneIDAClientManager()
			self.OneClientManagerBefore.Retrieve(before_filename)
		else:
			self.OneClientManagerBefore=self.IDAClientManager.GetOneIDAClientManagerFromSocket()
		print 'filename=',str(self.OneClientManagerBefore.GetClientFileInfo().orignal_file_path)
		if self.Mode=='retrieve':
			self.OneClientManagerAfter=DiffEngine.OneIDAClientManager()
			self.OneClientManagerAfter.Retrieve(after_filename)
		else:
			self.OneClientManagerAfter=self.IDAClientManager.GetOneIDAClientManagerFromSocket()
		self.OneIDAClientManagers.append(self.OneClientManagerBefore);
		print 'filename=',str(self.OneClientManagerAfter.GetClientFileInfo().orignal_file_path)
		self.OneIDAClientManagers.append(self.OneClientManagerAfter)

		self.DiffMachine=DiffEngine.DiffMachine(self.OneClientManagerBefore,self.OneClientManagerAfter)
		if self.Mode=='retrieve':
			self.DiffMachine.Retrieve(result_filename)
			os.unlink(before_filename)
			os.unlink(after_filename)
			os.unlink(result_filename)
			os.rmdir(tmp_path)
		else:
			self.DiffMachine.Analyze()

		match_info_size=self.DiffMachine.GetMatchInfoCount()
		treestore=gtk.TreeStore(str,gobject.TYPE_INT,gobject.TYPE_INT,gobject.TYPE_INT,str,gobject.TYPE_INT,gobject.TYPE_INT,gobject.TYPE_INT,gobject.TYPE_INT,gobject.TYPE_INT)
		self.Iter2Data={}
		self.MatchWithDifference=[{},{}]
		for i in range(0,match_info_size):
			match_info=self.DiffMachine.GetMatchInfo(i)
			if match_info.block_type==FUNCTION_BLOCK:
				#match_info.end_addr
				#match_info.block_type
				treestore.append(None,[match_info.name,
					match_info.addr,
					match_info.first_found_match,
					match_info.first_not_found_match,
					match_info.match_name,
					match_info.match_addr,
					match_info.second_found_match,
					match_info.second_not_found_match,
					match_info.first_found_match_with_difference,
					match_info.second_found_match_with_difference
					])
			if match_info.match_rate!=100:
				self.MatchWithDifference[0][match_info.addr]=1
				self.MatchWithDifference[1][match_info.match_addr]=1
		self.UnidentifiedBlocks=[{},{}]
		for index in range(0,2):
			for i in range(0,self.DiffMachine.GetUnidentifiedBlockCount(index)):
				code_block=self.DiffMachine.GetUnidentifiedBlock(index,i)
				self.UnidentifiedBlocks[index][int(code_block.start_addr)]=int(code_block.end_addr)
		gobject.idle_add(self.UpdateUI,treestore)
		if DoSyncWithIDA:
			self.DiffMachine.ShowResultsOnIDA()
			if self.IDAClientManager:
				self.IDAClientManager.IDACommandProcessor(self.OneClientManagerBefore,self.OneClientManagerAfter,self.DiffMachine)

	def UpdateUI(self,treestore):
		self.treestore=treestore
		self.tvw_diff_list.set_model(treestore)

	def GetMap(self,index,root_addr):
		map={}
		contents={}
		addrs=[root_addr]
		for addr in addrs:
			ret=self.OneIDAClientManagers[index].GetMappedAddresses(addr,CREF_FROM)
			if ret!=0:
				[addresses,size]=ret
				targets=[]
				for i in range(0,size):
					target=int(DiffEngine.GetDWORD(addresses,i))
					targets.append(target)
					if not map.has_key(target):
						addrs.append(target)
				map[addr]=targets
		large_mode=False
		if len(addrs)>100: # or self.DoSyncWithIDA:
			large_mode=True
		for addr in addrs:
			attrs={}
			attrs['name']=hex(addr)
			if large_mode:
				attrs['shape']='point'
			else:
				attrs['content']=self.OneIDAClientManagers[index].GetDisasmLines(addr,0)
				self.OneIDAClientManagers[index].FreeDisasmLines()
				attrs['shape']='record'
			if self.UnidentifiedBlocks[index].has_key(addr):
				attrs['fontcolor']='white'
				attrs['fillcolor']='red'
			elif self.MatchWithDifference[index].has_key(addr):
				attrs['fontcolor']='black'
				attrs['fillcolor']='yellow'
			else:
				attrs['fontcolor']='white'
				attrs['fillcolor']='black'
			contents[addr]=attrs
		return [map,contents]

if __name__=="__main__":
	gobject.threads_init()
	gtk.gdk.threads_init()
	diff_browser=DiffBrowser()
	gtk.gdk.threads_enter()
	gtk.main()
	gtk.gdk.threads_leave()

