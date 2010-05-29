import sys
sys.path.append('..')
import PatchDatabaseWrapper
import PatchTimeline
import DarunGrimSessions

from mako.template import Template

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
<body>
<%self:layoutdata somedata="${file_index_entry}" args="col">\
Body data: ${col}\
</%self:layoutdata>
</body>
</html>"""


class Worker:
	def __init__ ( self, database = r'..\test.db' ):
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

if __name__ == '__main__':
	worker = Worker()
	print worker.Patches()
