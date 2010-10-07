import sys
import types
import cherrypy
import urllib
import unittest
import re
import os

import PatchDatabaseWrapper
import PatchTimeline
import DarunGrimSessions
import DarunGrimDatabaseWrapper
import DarunGrimAnalyzers
import DownloadMSPatches

from mako.template import Template
from HTMLPages import *

config_file = 'DarunGrim3.cfg'

class WebServer(object):
	def __init__(self):
		#Something Configurable
		self.BinariesStorageDirectory = r'C:\mat\Projects\Binaries'
		self.MicrosoftBinariesStorageDirectory = self.BinariesStorageDirectory
		self.DGFDirectory = r'C:\mat\Projects\DGFs'
		self.IDAPath = None
		self.PatchTemporaryStore = 'Patches'

		if os.path.exists( config_file ):
			fd = open( config_file )
			config_data = fd.read()
			fd.close()
			config = ConfigParser.RawConfigParser()
			config.readfp(io.BytesIO( config_data ))
					
			self.BinariesStorageDirectory = os.path.join( os.getcwd(), config.get("Directories", "BinariesStorage") )
			self.MicrosoftBinariesStorageDirectory = self.BinariesStorageDirectory
			self.DGFDirectory = os.path.join( os.getcwd(), config.get("Directories", "DGFDirectory") )
			self.IDAPath = config.get("Directories", "IDAPath")
			self.DatabaseName = config.get("Directories", "DatabaseName")
			self.PatchTemporaryStore = config.get("Directories", "PatchTemporaryStore")
		
		#Operation
		self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )
		self.PatchTimelineAnalyzer = PatchTimeline.Analyzer( database = self.Database )

		self.DifferManager = DarunGrimSessions.Manager( self.DatabaseName, self.BinariesStorageDirectory, self.DGFDirectory, self.IDAPath )
		self.PatternAnalyzer = DarunGrimAnalyzers.PatternAnalyzer()

	def index(self):
		mytemplate = Template( IndexTemplateText )
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		patches = database.GetPatches()
		return mytemplate.render()
	index.exposed = True

	def ShowFileList(self, company_name = None, filename = None, version_string = None ):
		names = []
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		if company_name:
			if filename:
				if version_string:
					#Show info
					pass
				else:
					#List version strings
					file_information_list = []
					database = PatchDatabaseWrapper.Database( self.DatabaseName )
					for (id, version_string ) in database.GetVersionStringsWithIDs( company_name, filename ):
						file_information_list.append( (version_string,id,filename) )
					mytemplate = Template( FileListVersionStringsTemplateText, input_encoding='utf-8' , output_encoding='utf-8' )
					return mytemplate.render(  
						company_name = company_name,
						filename = filename,
						file_information_list = file_information_list,
						show_add_to_queue = True
					)
			else:
				#List filenames
				
				for (name, ) in database.GetFileNames( company_name ):
					names.append( name )

				mytemplate = Template( FileListFileNamesTemplateText, input_encoding='utf-8' , output_encoding='utf-8' )
				return mytemplate.render(  
					company_name = company_name,
					names = names
				)
		else:
			#List company_names
			for (name, ) in database.GetCompanyNames():
				names.append( name )
			mytemplate = Template( FileListCompanyNamesTemplateText, input_encoding='utf-8' , output_encoding='utf-8' )
			return mytemplate.render( names = names )
	ShowFileList.exposed = True

	def FileTree(self, company_name = None, filename = None, version_string = None ):
		return """<html>
<head>
	<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
	<script type="text/javascript" src="http://static.jstree.com/v.1.0rc2/jquery.js"></script>
	<script type="text/javascript" src="http://static.jstree.com/v.1.0rc2/jquery.cookie.js"></script>
	<script type="text/javascript" src="http://static.jstree.com/v.1.0rc2/jquery.hotkeys.js"></script>
	<script type="text/javascript" src="http://static.jstree.com/v.1.0rc2/jquery.jstree.js"></script>
</head> 

<body>
""" + MainMenu + """
<div id="demo1" class="demo"></div>
<script type="text/javascript">
$(function () {
	$("#demo1").jstree({
		"json_data" : 
			{ 
				// I chose an ajax enabled tree - again - as this is most common, and maybe a bit more complex
				// All the options are the same as jQuery's except for `data` which CAN (not should) be a function
				"ajax" : {
					// the URL to fetch the data
					"url" : "FileTreeJSON",
					// this function is executed in the instance's scope (this refers to the tree instance)
					// the parameter is the node being loaded (may be -1, 0, or undefined when loading the root nodes)
					"data" : function (n) { 
						// the result is fed to the AJAX request `data` option
						return { 
							"company_name" : n.attr ? n.attr("company_name"): "",
							"filename" : n.attr ? n.attr("filename"): "",
							"version_string" : n.attr ? n.attr("version_string"): ""
						}; 
					}
				}
			}
		,
		"plugins" : [ "themes", "json_data", "checkbox" ]
	});
});
</script>
</body>
</html>"""
	FileTree.exposed = True

	def FileTreeJSON(self, company_name = None, filename = None, version_string = None ):
		names = []
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		if company_name:
			if filename:
				if version_string:
					#Show info
					pass
				else:
					#List version strings
					print 'List version strings'
					#List filenames
					version_strings = []
					for (id, name, ) in database.GetVersionStringsWithIDs( company_name, filename ):
						tree_data = {}
						tree_data[ "data" ] = name
						tree_data[ "attr" ] = { "company_name": company_name, "filename": name }

						version_strings.append( tree_data )
					version_strings_json = json.dumps( version_strings )
					return version_strings_json
			else:
				print 'List filenames'
				#List filenames
				file_names = []
				for (name, ) in database.GetFileNames( company_name ):
					tree_data = {}
					tree_data[ "data" ] = name
					tree_data[ "attr" ] = { "company_name": company_name, "filename": name }
					tree_data[ "state" ] = "closed"

					file_names.append( tree_data )
				file_names_json = json.dumps( file_names )
				return file_names_json
		else:
			company_names = []
			for (name, ) in database.GetCompanyNames():
				tree_data = {}
				tree_data[ "data" ] = name
				tree_data[ "attr" ] = { "company_name": name, "rel": "drive" }
				tree_data[ "state" ] = "closed"

				company_names.append( tree_data )
			company_names_json = json.dumps( company_names )
			return company_names_json
	FileTreeJSON.exposed = True

	def ShowFileImport( self, folder = None ):
		mytemplate = Template( FileImportTemplateText )

		if folder:
			print 'folder=',folder
			file_store = FileStore.FileProcessor( 'index.db' )
			file_store.IndexFilesInFoler( folder , target_dirname = self.BinariesStorageDirectory )
		return mytemplate.render( folder = folder )
	ShowFileImport.exposed = True

	def ShowFileSearch( self, filename = None ):
		mytemplate = Template( """<%def name="layoutdata()">
			<form name="input" action="ShowFileSearch">
				<table>
				<tr>
					<td>Filename:&nbsp;&nbsp;</td>
					<td><input type="text" size="50" name="filename" value="" /> </td>
				</tr>
				<table>
				<p><input type="submit" value="Search"/>
			</form>
		</%def>
		""" + BodyHTML )

		if filename:
			database = PatchDatabaseWrapper.Database( self.DatabaseName )
			file_info_list = database.GetFileByFileNameWildMatch( filename )
			file_information_list = []
			for file_info in file_info_list:
				file_information_list.append( (file_info.filename,file_info.id,file_info.version_string) )

			mytemplate = Template( FileListVersionStringsTemplateText, input_encoding='utf-8' , output_encoding='utf-8' )
			return mytemplate.render(  
				company_name = "",
				filename = "",
				file_information_list = file_information_list,
				show_add_to_queue = True
			)
			
		return mytemplate.render()
	ShowFileSearch.exposed = True

	def ShowMSPatchList( self, operation = '' ):
		if operation == 'update':
			patch_downloader = DownloadMSPatches.PatchDownloader( self.PatchTemporaryStore, self.DatabaseName )
			patch_downloader.DownloadCurrentYearPatches()

		mytemplate = Template( PatchesTemplateText )
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		patches = database.GetPatches()
		return mytemplate.render( patches=patches )
	ShowMSPatchList.exposed = True

	def PatchInfo( self, id ):
		mytemplate = Template( PatchInfoTemplateText )
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		downloads = database.GetDownloadByPatchID( id )
		return mytemplate.render( id=id, downloads=downloads )
	PatchInfo.exposed = True

	def DownloadInfo(self, patch_id, id, operation = '' ):
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		if operation == 'extract':
			patch_temporary_folder = tempfile.mkdtemp()
			patch_temporary_folder2 = tempfile.mkdtemp()
			file_store = FileStore.MSFileProcessor( patch_temporary_folder, self.MicrosoftBinariesStorageDirectory, database = database )
			patch_downloader = DownloadMSPatches.PatchDownloader( patch_temporary_folder2, self.DatabaseName )
			for download in database.GetDownloadByID( id ):
				print 'Extracting', download.filename, download.url
				if not os.path.isfile( download.filename ):
					files = patch_downloader.DownloadFileByLink( download.url )
				file_store.ExtractDownload( download, files[0] )
			try:
				os.removedirs( patch_temporary_folder2 )
			except:
				pass

			try:
				os.removedirs( patch_temporary_folder )
			except:
				pass

		files = database.GetFileByDownloadID( id )

		mytemplate = Template( DownloadInfoTemplateText )
		return mytemplate.render( 
				patch_id = patch_id, 
				patch_name = database.GetPatchNameByID( patch_id ), 
				id = id,
				files = files 
			)
	DownloadInfo.exposed = True

	def FileInfo( self, patch_id, download_id, id ):
		#PatchTimeline
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		files = database.GetFileByID( id )
		print 'files', files
		[ file_index_entry ] = files
		filename = file_index_entry.filename
		target_patch_name = file_index_entry.downloads.patches.name

		source_id = 0
		source_patch_name = 'Not Found'
		source_filename = 'Not Found'
		target_filename = filename
		target_id = 0
		print 'FileInfo: filename=', filename
		for ( target_patch_name, target_file_entry, source_patch_name, source_file_entry ) in self.PatchTimelineAnalyzer.GetPatchPairsForAnalysis( filename = filename, id = id, patch_name = target_patch_name ):
			print '='*80
			print target_patch_name,source_patch_name

			source_filename = source_file_entry['full_path']
			source_id = source_file_entry['id']

			target_filename = target_file_entry['full_path']
			target_id = target_file_entry['id']

		mytemplate = Template( FileInfoTemplateText )
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		return mytemplate.render(
			patch_id = patch_id,
			patch_name = database.GetPatchNameByID( patch_id ), 
			download_id = download_id,
			download_label = database.GetDownloadLabelByID( download_id),
			id = id,
			file_index_entry=file_index_entry, 
			source_patch_name = source_patch_name, 
			source_filename = source_filename,
			source_id = source_id,
			target_patch_name = target_patch_name, 
			target_filename = target_filename,
			target_id = target_id
		)
	FileInfo.exposed = True

	## Project Related ############################################################
	def ShowProjects( self ):
		#Show Add form
		mytemplate = Template( """<%def name="layoutdata()">
			<table class="Table">
			% for item in items:
				<tr>
					<td><a href="ShowProject?project_id=${item.id}">${item.name}</a></td>
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

		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		items = database.GetProjects()	
		return mytemplate.render( items = items )
	ShowProjects.exposed = True

	def AddProject( self, name, description = '' ):
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		database.AddProject( name, description )
		database.Commit()		
		return self.ShowProjects()
	AddProject.exposed = True

	def ShowProject( self, project_id = None ):
		print 'ShowProject', project_id
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		project_members = database.GetProjectMembers( project_id )

		file_information_list = []
		for project_member in project_members:
			print project_member.projects.name, project_member.fileindexes.filename
			file_information_list.append( (project_member.fileindexes.filename,project_member.fileindexes.id,project_member.fileindexes.version_string) )

		mytemplate = Template( FileListVersionStringsTemplateText, input_encoding='utf-8' , output_encoding='utf-8' )
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
		
		database = PatchDatabaseWrapper.Database( self.DatabaseName )
		if not project_id:
			items = database.GetProjects()

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
			database.AddToProject( project_id, id )
			database.Commit()			
			return self.ShowProject( project_id )

	AddToProject.exposed = True
	##############################################################################
	
	def GenerateDGFName( self, source_id, target_id ):
		return os.path.join( self.DGFDirectory, str( source_id ) + '_' + str( target_id ) + '.dgf')
	
	def StartDiff( self, source_id, target_id, patch_id = 0, download_id = 0, file_id = 0, show_detail = 0 ):
		databasename = self.GenerateDGFName( source_id, target_id )
		self.DifferManager.InitFileDiffByID( source_id, target_id, databasename )
		print 'StartDiff Results: ', source_id,'/',target_id,'/', databasename
		return self.GetFunctionMatchInfo( 
			patch_id, 
			download_id, 
			file_id, 
			source_id=source_id, 
			target_id = target_id,
			show_detail  = show_detail
			)
	StartDiff.exposed = True

	def GetFunctionMatchInfo( self, patch_id, download_id, file_id, source_id, target_id, show_detail = 0 ):
		databasename = self.GenerateDGFName( source_id, target_id )
		database = DarunGrimDatabaseWrapper.Database( databasename )
		function_match_infos = []
		
		for function_match_info in database.GetFunctionMatchInfo():
			if function_match_info.non_match_count_for_the_source > 0 or \
				function_match_info.non_match_count_for_the_target > 0 or \
				function_match_info.match_count_with_modificationfor_the_source > 0:
				function_match_infos.append( function_match_info )

		patch_database = PatchDatabaseWrapper.Database( self.DatabaseName )
		source_file = patch_database.GetFileByID( source_id )[0]
		target_file = patch_database.GetFileByID( target_id )[0]

		mytemplate = Template( FunctionmatchInfosTemplateText )
		return mytemplate.render(
				source_file_name = source_file.filename,
				source_file_version_string = source_file.version_string,
				target_file_name = target_file.filename,
				target_file_version_string = target_file.version_string,		
				patch_id = patch_id, 
				patch_name = patch_database.GetPatchNameByID( patch_id ), 
				download_id = download_id, 
				download_label = patch_database.GetDownloadLabelByID( download_id),
				file_id = file_id, 
				file_name = patch_database.GetFileNameByID( file_id ),  
				source_id=source_id, 
				target_id = target_id, 
				function_match_infos = function_match_infos,
				show_detail = 0
			)

	def ShowFunctionMatchInfo( self, patch_id, download_id, file_id, source_id, target_id ):
		return self.GetFunctionMatchInfo( patch_id, download_id, file_id, source_id, target_id )
	ShowFunctionMatchInfo.exposed = True

	def ShowBasicBlockMatchInfo( self, patch_id, download_id, file_id, source_id, target_id, source_address, target_address ):
		return self.GetDisasmComparisonTextByFunctionAddress( patch_id, download_id, file_id, source_id, target_id, source_address, target_address )
	ShowBasicBlockMatchInfo.exposed = True

	def GetDisasmComparisonTextByFunctionAddress( self, 
			patch_id, download_id, file_id, 
			source_id, target_id, source_address, target_address, 
			source_function_name = None, target_function_name = None ):

		patch_database = PatchDatabaseWrapper.Database( self.DatabaseName )
		source_file = patch_database.GetFileByID( source_id )[0]
		target_file = patch_database.GetFileByID( target_id )[0]
	
		databasename = self.GenerateDGFName( source_id, target_id )
		darungrim_database = DarunGrimDatabaseWrapper.Database( databasename )

		source_address = int(source_address)
		target_address = int(target_address)

		self.DifferManager.ShowAddresses( source_id, target_id, source_address, target_address )

		if not source_function_name:
			source_function_name = darungrim_database.GetBlockName( 1, source_address )

		if not target_function_name:
			target_function_name = darungrim_database.GetBlockName( 2, target_address )
		
		comparison_table = darungrim_database.GetDisasmComparisonTextByFunctionAddress( source_address, target_address )
		text_comparison_table = []

		left_line_security_implications_score_total = 0
		right_line_security_implications_score_total = 0
		for ( left_address, left_lines, right_address, right_lines, match_rate ) in comparison_table:
			left_line_security_implications_score = 0
			right_line_security_implications_score = 0
			if (right_address == 0 and left_address !=0) or match_rate < 100 :
				( left_line_security_implications_score, left_line_text ) = self.PatternAnalyzer.GetDisasmLinesWithSecurityImplications( left_lines, right_address == 0 )
			else:
				left_line_text = "<p>".join( left_lines )

			if (left_address == 0 and right_address !=0) or match_rate < 100 :
				( right_line_security_implications_score, right_line_text ) = self.PatternAnalyzer.GetDisasmLinesWithSecurityImplications( right_lines, left_address == 0 )
			else:
				right_line_text = "<p>".join( right_lines )

			left_line_security_implications_score_total += left_line_security_implications_score
			right_line_security_implications_score_total += right_line_security_implications_score
			text_comparison_table.append(( left_address, left_line_text, right_address, right_line_text, match_rate ) )
		
		( source_address_infos, target_address_infos ) = darungrim_database.GetBlockAddressMatchTableByFunctionAddress( source_address, target_address )
		self.DifferManager.ColorAddresses( source_id, target_id, source_address_infos, target_address_infos )

		mytemplate = Template( ComparisonTableTemplateText )
		return mytemplate.render(
				source_file_name = source_file.filename,
				source_file_version_string = source_file.version_string,
				target_file_name = target_file.filename,
				target_file_version_string = target_file.version_string,
				source_function_name = source_function_name, 
				target_function_name = target_function_name,
				comparison_table = text_comparison_table, 
				source_id = source_id, 
				target_id = target_id, 
				source_address = source_address,
				target_address = target_address,
				patch_id = patch_id, 
				patch_name = patch_database.GetPatchNameByID( patch_id ), 
				download_id = download_id, 
				download_label = patch_database.GetDownloadLabelByID( download_id),
				file_id = file_id,
				file_name = patch_database.GetFileNameByID( file_id ),  
			)

	def SyncIDA( self, source_id, target_id ):
		self.DifferManager.SyncIDA( source_id, target_id )
		return "<body> Check your IDA </body>"
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

