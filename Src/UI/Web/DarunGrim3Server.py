import sys
import types
import cherrypy
import urllib
import unittest
import re
import HTMLGenerator
import os
from mako.template import Template

MainBody = """
		<div id=Content>
		<%self:layoutdata args="col">\
		</%self:layoutdata>
		</div>
		</body>
		</html>"""

BodyHTML = """
<html>
""" + HTMLGenerator.HeadText + """
<body>
""" + HTMLGenerator.MainMenu + MainBody 

config_file = 'DarunGrim3.cfg'

class WebServer(object):
	def __init__(self):
		pass

	def index(self):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.Index()
	index.exposed = True

	def ShowFileList(self, company_name = None, filename = None, version_string = None ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )	
		return html_worker.ShowFileList( company_name , filename , version_string )
	ShowFileList.exposed = True

	def FileTree(self, company_name = None, filename = None, version_string = None ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )	
		return html_worker.FileTree( company_name , filename , version_string )
	FileTree.exposed = True

	def FileTreeJSON(self, company_name = None, filename = None, version_string = None ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )	
		return html_worker.FileTreeJSON( company_name , filename , version_string )
	FileTreeJSON.exposed = True

	def ShowFileImport( self, folder = None ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )	
		return html_worker.ShowFileImport( folder )
	ShowFileImport.exposed = True

	def ShowMSPatchList(self, operation = '' ):
		print 'ShowMSPatchList'
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.ShowMSPatchList( operation )
	ShowMSPatchList.exposed = True

	def PatchInfo(self,id):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.PatchInfo( id )
	PatchInfo.exposed = True

	def DownloadInfo(self, patch_id, id, operation = '' ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.DownloadInfo( patch_id, id, operation )
	DownloadInfo.exposed = True

	def FileInfo(self, patch_id, download_id, id):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.FileInfo( patch_id, download_id, id )
	FileInfo.exposed = True

	## Project Related ############################################################
	def ShowProjects( self ):
		#Show Add form
		mytemplate = Template( """<%def name="layoutdata()">
			<table class="Table">
			% for item in items:
				<tr>
					<td><a href="EditProject?id=${id}&id=${item.id}">${item.name}</a></td>
					<td>${item.name}</td>
				</tr>
			% endfor
			</table>

			<form name="input" action="AddProject">
				<table>
				<tr>
					<td>Name</td>
					<td><input type="text" size="50" name="name" value="" /> </td>
				</tr>
				<tr>
					<td>Description</td>
					<td><input type="text" size="50" name="description" value="" /></td>
				</tr>
				<table>
				<p><input type="submit" value="Add"/>
			</form>
		</%def>
		""" + BodyHTML )

		html_worker = HTMLGenerator.Worker( config_file = config_file )
		items = html_worker.GetProjects()

		return mytemplate.render( items = items )
	ShowProjects.exposed = True

	def AddProject( self, name, description = '' ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		html_worker.AddProject( name, description )
		return self.ShowProjects()
	AddProject.exposed = True

	def ShowProject( self, project_id = None ):
		print 'ShowProject', project_id
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		project_members = html_worker.GetProjectMembers( project_id )		

		file_information_list = []
		for project_member in project_members:
			print project_member.projects.name, project_member.fileindexes.filename
			file_information_list.append( (project_member.fileindexes.filename,project_member.fileindexes.id,project_member.fileindexes.version_string) )

		mytemplate = Template( HTMLGenerator.FileListVersionStringsTemplateText, input_encoding='utf-8' , output_encoding='utf-8' )
		return mytemplate.render(  
			company_name = "",
			filename = "",
			file_information_list = file_information_list,
			show_add_to_queue = False
		)
	ShowProject.exposed = True

	def AddToProject( self, id, project_id = None ):
		#Display project choose list
		items = []
		if not project_id:
			html_worker = HTMLGenerator.Worker( config_file = config_file )
			items = html_worker.GetProjects()

			mytemplate = Template( """<%def name="layoutdata()">
				<form name="input" action="AddToProject">
					<select name="project_id">
					% for item in items:
						<option value=${item.id}>${item.name}</option>
					% endfor
					</select>
					<input type="hidden" name="id" value="${id}"/>
					<input type="submit" value="Choose"/>
				</form>
			</%def>
			""" + BodyHTML )

			return mytemplate.render( id = id, items = items )
		else:
			#TODO Add to project
			html_worker = HTMLGenerator.Worker( config_file = config_file )
			html_worker.AddToProject( project_id, id )			
			return self.ShowProject( project_id )

	AddToProject.exposed = True
	##############################################################################
	
	def StartDiff( self, source_id, target_id, patch_id = 0, download_id = 0, file_id = 0, show_detail = 0 ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.StartDiff( patch_id, download_id, file_id, source_id, target_id, show_detail )
	StartDiff.exposed = True

	def ShowFunctionMatchInfo( self, patch_id, download_id, file_id, source_id, target_id ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.GetFunctionMatchInfo( patch_id, download_id, file_id, source_id, target_id )
	ShowFunctionMatchInfo.exposed = True

	def ShowBasicBlockMatchInfo( self, patch_id, download_id, file_id, source_id, target_id, source_address, target_address ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.GetDisasmComparisonTextByFunctionAddress( patch_id, download_id, file_id, source_id, target_id, source_address, target_address )
	ShowBasicBlockMatchInfo.exposed = True

	def SyncIDA( self, source_id, target_id ):
		html_worker = HTMLGenerator.Worker( config_file = config_file )
		return html_worker.SyncIDA( source_id, target_id )
	SyncIDA.exposed = True

if __name__ == '__main__':
	import ConfigParser
	import io
	import sys

	if len( sys.argv ) > 1:
		config_file = sys.argv[1]

	print 'Configuration file is' + config_file
	fd = open( config_file )
	config_data = fd.read()
	fd.close()

	config = ConfigParser.RawConfigParser()
	config.readfp(io.BytesIO( config_data ))
					
	port = int( config.get("Global", "Port") )

	cherrypy.config.update({'server.socket_host': '127.0.0.1',
                        'server.socket_port': port,
    			'response.timeout': 1000000
                       })
	config = {
		'/data': {
			'tools.staticdir.on': True,
			'tools.staticdir.dir': os.path.join(os.getcwd(), 'data'),
			'tools.staticdir.content_types': {
				'js': 'application/javascript',
				'atom': 'application/atom+xml'
			}
		}
	}
	
	cherrypy.tree.mount( WebServer(), config=config )
	cherrypy.engine.start()
	cherrypy.engine.block()

