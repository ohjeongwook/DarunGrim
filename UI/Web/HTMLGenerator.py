import sys
TestDir =  r'..\..\Bin Collector'
sys.path.append( TestDir )
sys.path.append(r'..\..\Diff Inspector')
import os
import PatchDatabaseWrapper
import PatchTimeline
import DarunGrimSessions
import DarunGrimDatabaseWrapper

from mako.template import Template

CSSText = """
<style type="text/css">
div.Message
{
	width: expression(document.body.clientWidth > 1000) ? "1000px" : "auto";
	max-width: 1000px;
	overflow: scroll;
	font-size:80%;
}

table.Table {
	border-width: 1px;
	border-spacing: 2px;
	border-style: dotted;
	border-color: green;
	border-collapse: separate;
	background-color: white;
	width: expression(document.body.clientWidth > 1000) ? "1000px" : "auto";
	max-width: 1000px;
}

table.Table tr {
	border-width: 1px;
	padding: 1px;
	border-style: dashed;
	border-color: gray;
	background-color: rgb(f0, f0, f0);
	-moz-border-radius: 0px 0px 0px 0px;
	overflow: hidden;
	max-width: 1000px;
}

table.Table td {
	border-width: 1px;
	padding: 1px;
	border-style: dashed;
	border-color: gray;
	background-color: rgb(f0, f0, f0);
	-moz-border-radius: 0px 0px 0px 0px;
	overflow: hidden;
	max-width: 1000px;
}

table.TableTitleLine td {
	border-width: 1px;
	padding: 1px;
	border-style: dashed;
	border-color: gray;
	background-color: rgb(60, a0, f0);
	-moz-border-radius: 0px 0px 0px 0px;
	overflow: hidden;
	max-width: 1000px;
}
</style>
"""

PatchesTemplateText = """<%def name="layoutdata(somedata)">
	<table>
	% for item in somedata:
		<tr>
			<td><a href="PatchInfo?id=${item.id}">${item.name}</a></td>
			<td>${item.title}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
""" + CSSText + """
<body>
<%self:layoutdata somedata="${patches}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

PatchInfoTemplateText = """<%def name="layoutdata(somedata)">
	<table>
	% for item in somedata:
		<tr>
			<td><a href="DownloadInfo?id=${item.id}">${item.label}</a></td>
			<td>${item.filename}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
""" + CSSText + """
<body>
<%self:layoutdata somedata="${downloads}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

DownloadInfoTemplateText = """<%def name="layoutdata(somedata)">
	<table>
	% for item in somedata:
		<tr>
			<td><a href="FileInfo?id=${item.id}">${item.filename}</a></td>
			<td>${item.version_string}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
<body>
<%self:layoutdata somedata="${files}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

FileInfoTemplateText = """<%def name="layoutdata(somedata)">
<p>${somedata.company_name}, ${somedata.operating_system}, ${somedata.service_pack}
<p>${somedata.filename}
<p>${source_patch_name}: ${source_filename}
<p>${target_patch_name}: ${target_filename}
</%def>
<html>
""" + CSSText + """
<body>
<%self:layoutdata somedata="${file_index_entry}" args="col">\
Body data: ${col}\
</%self:layoutdata>
<form name="input" action="StartDiff" method="get">
<input type="hidden" name="source_id" value="${source_id}"/>
<input type="hidden" name="target_id" value="${target_id}"/>
<input type="submit" value="Start Diffing" />
</form> 
</body>
</html>"""

DiffInfoTemplateText = """<%def name="layoutdata(somedata)">
<p><a href="file://${storage_filename}"> Result File </a>
</%def>
<html>
""" + CSSText + """
<body>
<%self:layoutdata somedata="${file_index_entry}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

FunctionmatchInfosTemplateText = """<%def name="layoutdata(function_match_infos)">
<p>
	<table>
		<tr>
			<td>Source Function Name</td>
			<td>Target Function Name</td>
			<td>Match Count</td>
			<td>Match Count With Modifications</td>
			<td>Non Match Count for Source</td>
			<td>Non Match Count For Target</td>
		</tr>
	% for function_match_info in function_match_infos:
		<tr>
			<td>${function_match_info.source_function_name} (${hex(function_match_info.source_address)})</td>
			<td>${function_match_info.target_function_name} (${hex(function_match_info.target_address)})</td>
			<td>${function_match_info.match_count_for_the_source}</td>
			<td>${function_match_info.match_count_with_modificationfor_the_source}</td>
			<td>${function_match_info.non_match_count_for_the_source}</td>
			<td>${function_match_info.non_match_count_for_the_target}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
""" + CSSText + """
<body>
<%self:layoutdata function_match_infos="${function_match_infos}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""

"""
str(function_match_info.block_type)
str(function_match_info.type)
str( function_match_info.match_rate )
"""

ComparisonTableTemplateText = """<%def name="layoutdata(comparison_table)">
<p>
	<table class="Table">
		<tr>
			<td>Source</td>
			<td>Target</td>
		</tr>
	% for ( left_address, left_lines, right_address, right_lines ) in comparison_table:
		<tr>
			<td>
			% if left_address != 0:
				${hex(left_address)}
			% endif
			<p>${left_lines}</td>
			<td>
			% if right_address != 0:
				${hex(right_address)}
			% endif
			<p>${right_lines}</td>
		</tr>
	% endfor
	</table>
</%def>
""" + CSSText + """
<%self:layoutdata comparison_table="${comparison_table}" args="col">\
Body data: ${col}\
</%self:layoutdata>
"""

class Worker:
	def __init__ ( self, database = os.path.join( TestDir, 'test.db' ) ):
		self.DatabaseName = database
		self.Database = PatchDatabaseWrapper.Database( self.DatabaseName )
		self.PatchTimelineAnalyzer = PatchTimeline.Analyzer( database = self.Database )

	def Patches( self ):
		mytemplate = Template( PatchesTemplateText )
		patches = self.Database.GetPatches()
		return mytemplate.render( patches=patches )

	def PatchInfo( self, id ):
		mytemplate = Template( PatchInfoTemplateText )
		downloads = self.Database.GetDownloadByPatchID( id )
		return mytemplate.render( downloads=downloads )

	def DownloadInfo( self, id ):
		mytemplate = Template( DownloadInfoTemplateText )
		files = self.Database.GetFileByDownloadID( id )
		return mytemplate.render( files=files )

	def FileInfo( self, id ):
		#PatchTimeline
		[ file_index_entry ] = self.Database.GetFileByID( id )
		filename = file_index_entry.filename
		target_patch_name = file_index_entry.downloads.patches.name

		source_id = 0
		source_patch_name = 'Not Found'
		source_filename = 'Not Found'
		target_filename = 'Not Found'
		target_id = 0
		for ( target_patch_name, target_file_entry, source_patch_name, source_file_entry ) in self.PatchTimelineAnalyzer.GetPatchPairsForAnalysis( filename = filename, id = id, patch_name = target_patch_name ):
			print '='*80
			print target_patch_name,source_patch_name

			source_filename = source_file_entry['full_path']
			source_id = source_file_entry['id']

			target_filename = target_file_entry['full_path']
			target_id = target_file_entry['id']

		mytemplate = Template( FileInfoTemplateText )
		return mytemplate.render(
			file_index_entry=file_index_entry, 
			source_patch_name = source_patch_name, 
			source_filename = source_filename,
			source_id = source_id,
			target_patch_name = target_patch_name, 
			target_filename = target_filename,
			target_id = target_id
		)

	def StartDiff( self, source_id, target_id ):
		print 'StartDiff', source_id,target_id
		file_differ = DarunGrimSessions.Manager(r'..\test.db')
		storage_filename = file_differ.InitFileDiffByID( source_id, target_id )
		print 'StartDiff: ', source_id,'/',target_id,'/', storage_filename
		mytemplate = Template( DiffInfoTemplateText )
		return mytemplate.render( storage_filename = storage_filename )

	def GetFunctionMatchInfo( self, databasename ):
		database = DarunGrimDatabaseWrapper.Database( databasename )
		function_match_infos = []
		for function_match_info in database.GetFunctionMatchInfo():
			if function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
				function_match_infos.append( function_match_info )
		mytemplate = Template( FunctionmatchInfosTemplateText )
		return mytemplate.render( function_match_infos = function_match_infos )

	def GetDisasmComparisonTextByFunctionAddress( self, databasename, source_address, target_address ):
		database = DarunGrimDatabaseWrapper.Database( databasename )
		comparison_table = database.GetDisasmComparisonTextByFunctionAddress( source_address, target_address )
		text_comparison_table = []
		for ( left_address, left_lines, right_address, right_lines ) in comparison_table:
			left_line_text = "<p>".join( left_lines )
			right_line_text = "<p>".join( right_lines )
			text_comparison_table.append(( left_address, left_line_text, right_address, right_line_text ) )
		mytemplate = Template( ComparisonTableTemplateText )
		return mytemplate.render( comparison_table = text_comparison_table )

	def GetDisasmComparisonText( self, databasename ):
		database = DarunGrimDatabaseWrapper.Database( databasename )
		function_match_infos = []
		ret = ''
		for function_match_info in database.GetFunctionMatchInfo():
			if function_match_info.non_match_count_for_the_source > 0 or function_match_info.non_match_count_for_the_target > 0:
				ret += worker.GetDisasmComparisonTextByFunctionAddress( databasename, function_match_info.source_address, function_match_info.target_address )  
		return ret

if __name__ == '__main__':
	worker = Worker()
	#print worker.Patches()
	databasename = r'..\..\Diff Inspector\Samples\MS06-040-MS04-022-netapi32.dgf'
	#print worker.GetFunctionMatchInfo( databasename )
	#print worker.GetDisasmComparisonTextByFunctionAddress( databasename, 0x71c21d00, 0x5b870058 )
	print worker.GetDisasmComparisonTextByFunctionAddress( databasename, 0x71c40a4a,0x5b893ab1 )  
	#print worker.GetDisasmComparisonText( databasename )
