MainMenu = """
<P>[ 
<a href="/ShowProjects">Projects</a> / 
<a href="/ShowFileImport">Files Import</a> / 
<a href="/ShowFileList">Files List</a> / 
<a href="/ShowFileSearch">File Search</a> / 
<a href="/ShowMSPatchList">Microsoft Patches List</a> / 
<a href="/">About</a> 
]
<P>
"""

BannerText = """
<PRE>
      ___           ___           ___           ___           ___
     /\  \         /\  \         /\  \         /\__\         /\__\    
    /::\  \       /::\  \       /::\  \       /:/  /        /::|  |   
   /:/\:\  \     /:/\:\  \     /:/\:\  \     /:/  /        /:|:|  |   
  /:/  \:\__\   /::\~\:\  \   /::\~\:\  \   /:/  /  ___   /:/|:|  |__ 
 /:/__/ \:|__| /:/\:\ \:\__\ /:/\:\ \:\__\ /:/__/  /\__\ /:/ |:| /\__\ 
 \:\  \ /:/  / \/__\:\/:/  / \/_|::\/:/  / \:\  \ /:/  / \/__|:|/:/  /
  \:\  /:/  /       \::/  /     |:|::/  /   \:\  /:/  /      |:/:/  / 
   \:\/:/  /        /:/  /      |:|\/__/     \:\/:/  /       |::/  /  
    \::/__/        /:/  /       |:|  |        \::/  /        /:/  /   
     ~~            \/__/         \|__|         \/__/         \/__/    
      ___           ___                       ___     
     /\  \         /\  \          ___        /\__\    
    /::\  \       /::\  \        /\  \      /::|  |   
   /:/\:\  \     /:/\:\  \       \:\  \    /:|:|  |   
  /:/  \:\  \   /::\~\:\  \      /::\__\  /:/|:|__|__ 
 /:/__/_\:\__\ /:/\:\ \:\__\  __/:/\/__/ /:/ |::::\__\ 
 \:\  /\ \/__/ \/_|::\/:/  / /\/:/  /    \/__/~~/:/  /
  \:\ \:\__\      |:|::/  /  \::/__/           /:/  / 
   \:\/:/  /      |:|\/__/    \:\__\          /:/  /  
    \::/  /       |:|  |       \/__/         /:/  /   
     \/__/         \|__|                     \/__/    


</PRE>

<P ALIGN="RIGHT">
Made by <a href="http://twitter.com/ohjeongwook" target="_new">Jeongwook "Matt" Oh<a>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</P>
<p ALIGN="RIGHT">
<a href="mailto:oh.jeongwook@gmail.com">Bug Reporting & Feature Requests<a>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</P>
<p ALIGN="RIGHT">
<a href="http://darungrim.org" target="_new">DarunGrim Main Site<a>
&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
</P>

"""

HeadText = """
	<link rel="stylesheet" href="/data/themes/smoothness/jquery-ui-1.8.5.custom.css">
	<link rel="stylesheet" href="/data/themes/basic/style.css"/>

    <script src="/data/jquery/jquery-1.4.3.min.js"></script>
    <script src="/data/jquery/ui/jquery.ui.core.js"></script>
    <script src="/data/jquery/ui/jquery.ui.widget.js"></script>
    <script src="/data/jquery/ui/jquery.ui.datepicker.js"></script>
    
    <script type="text/javascript" src="/data/jquery/tablesorter/jquery.tablesorter.js"></script> 

<script type="text/javascript">
	$(document).ready(function() 
		{ 
			$("#datepicker_from").datepicker();
			$("#datepicker_to").datepicker();
			$("#mainTable").tablesorter( {sortList:[[0,0],[2,1]], widgets: ['zebra']} ); 			
		} 
	);

	function checkAll(){
		for (var i=0;i<document.forms[0].elements.length;i++)
		{
			var e=document.forms[0].elements[i];
			if ((e.name != 'allbox') && (e.type=='checkbox'))
			{
				e.checked=document.forms[0].allbox.checked;
			}
		}
	}
</script>
"""

IndexTemplateText = """<%def name="layoutdata()">
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata args="col">\
</%self:layoutdata>
</div>

""" + BannerText + """
</body>
</html>"""

PatchesTemplateText = """<%def name="layoutdata(somedata)">
	<table class="Table">
	% for item in somedata:
		<tr>
			<td><a href="PatchInfo?id=${item.id}">${item.name}</a></td>
			<td>${item.title}</td>
		</tr>
	% endfor
	</table>
	<a href="/ShowMSPatchList?operation=update">Check for MS Patches Updates</a>
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata somedata="${patches}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

PatchInfoTemplateText = """<%def name="layoutdata(somedata)">
<p><a href="/ShowMSPatchList">List</a>
	<table class="Table">
	% for item in somedata:
		<tr>
			<td><a href="DownloadInfo?patch_id=${id}&id=${item.id}">${item.label}</a></td>
			<td>${item.filename}</td>
		</tr>
	% endfor
	</table>
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata somedata="${downloads}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

DownloadInfoTemplateText = """<%def name="layoutdata(somedata)">
<p><a href="/ShowMSPatchList">List</a>
&gt;<a href="PatchInfo?id=${patch_id}">${patch_name}</a>
	<table class="Table">
	% for item in somedata:
		<tr>
			<td><a href="FileInfo?patch_id=${patch_id}&download_id=${id}&id=${item.id}">${item.filename}</a></td>
			<td>${item.version_string}</td>
		</tr>
	% endfor
	</table>

	% if len( somedata ) == 0:
		<p><a href="/DownloadInfo?patch_id=${patch_id}&id=${id}&operation=extract">Download and Extract Patches Automatically</a> <p>(In case this fails, you need to extract and upload files manually)
	% endif
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata somedata="${files}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

FileInfoTemplateText = """<%def name="layoutdata(somedata)">
<p><a href="/ShowMSPatchList">List</a>
&gt;<a href="PatchInfo?id=${patch_id}">${patch_name}</a>
&gt;<a href="DownloadInfo?patch_id=${patch_id}&id=${download_id}">${download_label}</a>
	<table class="Table">
		<tr>
			<td>Company Name</td>
			<td>${somedata.company_name}</td>
		</tr>
		<tr>
			<td>Operating System</td>
			<td>${somedata.operating_system}</td>
		</tr>
		<tr>
			<td>Service Pack</td>
			<td>${somedata.service_pack}</td>
		</tr>
		<tr>
			<td>Filename</td>
			<td>${somedata.filename}</td>
		</tr>
		<tr>
			<td>Unpatched Filename</td>
			<td>${source_patch_name}: ${source_filename}</td>
		</tr>
		<tr>
			<td>Patched Filename</td>
			<td>${target_patch_name}: ${target_filename}</td>
		</tr>
	</table>
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata somedata="${file_index_entry}" args="col">\
</%self:layoutdata>
<form name="input" action="StartDiff" method="get">
<input type="hidden" name="patch_id" value="${patch_id}"/>
<input type="hidden" name="download_id" value="${download_id}"/>
<input type="hidden" name="file_id" value="${id}"/>
<input type="hidden" name="source_id" value="${source_id}"/>
<input type="hidden" name="target_id" value="${target_id}"/>
<input type="submit" value="Start Diffing" />
</form> 
</div>
</body>
</html>"""

DiffInfoTemplateText = """<%def name="layoutdata(somedata)">
<META HTTP-EQUIV="Refresh" CONTENT="1; URL="ShowFunctionMatchInfo?source_id=${source_id}&target_id=${target_id}">
<p><a href="ShowFunctionMatchInfo?databasename=source_id=${source_id}&target_id=${target_id}">Show Function Match Table</a>
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata somedata="${file_index_entry}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

FileListCompanyNamesTemplateText = """<%def name="layoutdata( filenames )">
<title>Company Names</title>
	<table class="Table">
	<tr>
	% for i, filename in enumerate(filenames):
		<td><a href="/ShowFileList?company_name=${filename}">${filename}</a></td>
		% if i % 5 == 4:
			</tr><tr>
		% endif
	% endfor
	</tr>
	</table>
</%def>
<html>
""" + HeadText + """

<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata filenames="${filenames}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

FileListFileNamesTemplateText = """<%def name="layoutdata(company_name, filenames, numVersions)">
<title>File Names for ${company_name}</title>
    Total <b>${len(filenames)}</b> files for <b>${company_name}</b><br>
	Back to <a href="/ShowFileList">Company Names</a>
	<table class="Table">
    <tr>
        <th>FILENAME</th>
        <th># of versions</th>
    </tr>
	% for i, filename in enumerate(filenames):
        <tr>
            <td><a href="/ShowFileList?company_name=${company_name}&filename=${filename}">${filename}</a></td>
            <td>${numVersions[i]}</td>
        </tr>
	% endfor
	</table>
</%def>
<html>
""" + HeadText + """

<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata company_name="${company_name}" filenames="${filenames}" numVersions="${numVersions}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

ProjectSelectionListTemplate = """
		<select name="project_id">
		% for project in projects:
			<option value=${project.id}>${project.name}</option>
		% endfor
		</select>
"""

ProjectSelectionTemplate = """<%def name="layoutdata()">
	<form name="input" action="AddToProject">
""" + ProjectSelectionListTemplate + """

		% for one_id in ids:
			<input type="hidden" name="id" value="${one_id}"/>
		% endfor

		<input type="submit" value="Choose"/>
	</form>
</%def>
"""

FileListTemplate = """<%def name="layoutdata(company_name, filename, version_string, file_information_list)">
<title>Version String for ${company_name}:${filename}</title>
	<p><a href="/ShowFileList?company_name=${company_name}">${company_name}</a>
	<form name="input" action="AddToProject">
		<table id="mainTable" class="SortedTable">

		<thead>
		<tr>
			<th></th>
			<th>Filename</th>
			<th>Version String</th>
			<th>Creation</th>
			<th>Modification</th>
			<th>Addition Time</th>
			<th>MD5</th>
			<th>SHA1</th>
			<th>Arch.</th>
			<th>Operation</th>
		</tr>
		</thead>

		<tbody>
		% for (name,ctime_str,mtime_str,add_time_str,md5,sha1,id,version_str,project_member_id, arch_info) in file_information_list:
			<tr>
				<td>
					<input type="checkbox" name="id" value="${id}" />
				</td>
			
				<td>${name}</td>
				<td>${version_str}</td>
				<td>${ctime_str}</td>
				<td>${mtime_str}</td>
				<td>${add_time_str}</td>
				<td>${md5}</td>
				<td>${sha1}</td>
				<td>${arch_info}</td>
				<td>
					<a href=OpenInIDA?id=${id} target=_new>Open</a>
				</td>
			</tr>
		% endfor

		</tr>
		</tbody>
		</table>
		
		<p><input type="checkbox" value="on" name="allbox" onclick="checkAll();"/>Check All Items
		<p><input type="submit" value="Add Checked Files To "/> Existing Project: 
		
""" + ProjectSelectionListTemplate + """
	or New Project: &nbsp; <input type="text" name="new_project_name" value=""/>
	</form> 
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata company_name="${company_name}" filename="${filename}" version_string="${version_string}" file_information_list="${file_information_list}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

ProjectContentTemplate = """<%def name="layoutdata(company_name, filename, version_string, file_information_list)">
<title>Version String for ${company_name}:${filename}</title>
	<p><a href="/ShowFileList?company_name=${company_name}">${company_name}</a>
	<form name="input" action="ProcessProjectContent">
		<table id="mainTable" class="SortedTable">

		<thead>
		<tr>
			<th></th>
			<th>Unpatched</th>
			<th>Patched&nbsp;&nbsp;</th>
			<th>Filename</th>
			<th>Version String</th>
			<th>Creation</th>
			<th>Modification</th>
			<th>Addition Time</th>
			<th>MD5</th>
			<th>SHA1</th>
			<th>Operation</th>
		</tr>
		</thead>

		<tbody>
		% for (name,ctime_str,mtime_str,add_time_str,md5,sha1,id,version_str,project_member_id) in file_information_list:
			<tr>
				<td>
					<input type="checkbox" name="project_member_id" value="${project_member_id}" />
				</td>
				<td>
					<input type="radio" name="source_id" value="${id}" />
				</td>	
				<td>
					<input type="radio" name="target_id" value="${id}" />
				</td>

				<td>${name}</td>
				<td>${version_str}</td>
				<td>${ctime_str}</td>
				<td>${mtime_str}</td>
				<td>${add_time_str}</td>
				<td>${md5}</td>
				<td>${sha1}</td>
				<td>
					<a href=OpenInIDA?id=${id} target=_new>Open</a>
				</td>
			</tr>
		% endfor
		</tbody>
		
		</table>
		<input type="hidden" name="project_id" value="${project_id}"/>
		<p>
		<p><input type="checkbox" value="on" name="allbox" onclick="checkAll();"/>Check all
		<input type="submit" name="operation" value="Remove From Project"/>		
		<input type="submit" name="operation" value="Start Diffing"/>		
	</form>

	% if project_result_list and len( project_result_list ) > 0:
		<hr>
		<h2> Results </h2>
		% for (source_id, target_id, source_file_name, source_file_version_string, target_file_name, target_file_version_string) in project_result_list:
			<p><a href="/StartDiff?source_id=${source_id}&target_id=${target_id}">${source_file_name}: ${source_file_version_string} VS 
			% if source_file_name != target_file_name:
				${target_file_name}: 
			% endif
			${target_file_version_string}</a>
		% endfor
	% endif
</%def>
<html>
""" + HeadText + """
<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata company_name="${company_name}" filename="${filename}" version_string="${version_string}" file_information_list="${file_information_list}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

FileImportTemplateText = """<%def name="layoutdata( folder )">
	<form name="input" action="ShowFileImport">
		<input type="text" size="50" name="folder" value="" /> 
		<p><input type="checkbox" name="move_file" value="yes" /> Move Files&nbsp;<B><font color="red">(WARNING: This will remove the source files)</font></B>
		<p><input type="checkbox" name="overwrite_mode" value="yes" /> Overwrite old entry
		<p><input type="submit" value="Import"/>
	</form>
	
	% if folder != None:
		Import from ${folder}
	% endif
</%def>
<html>
""" + HeadText + """

<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata folder = "${folder}" args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

FunctionmatchInfosTemplateText = """<%def name="layoutdata(source_file_name, 
	source_file_version_string, 
	target_file_name, 
	target_file_version_string, 
	show_detail, function_match_infos)">
%if patch_name:
	<p><a href="/ShowMSPatchList">List</a>
	&gt;<a href="PatchInfo?id=${patch_id}">${patch_name}</a>
%endif

%if download_label:
	&gt;<a href="DownloadInfo?patch_id=${patch_id}&id=${download_id}">${download_label}</a>
%endif

%if file_name:
	&gt;<a href="FileInfo?patch_id=${patch_id}&download_id=${download_id}&id=${file_id}">${file_name}</a>
%endif

&nbsp; [<a href="SyncIDA?source_id=${source_id}&target_id=${target_id}" target="sync_ida">Open IDA</a>]
&nbsp; [<a href="/StartDiff?source_id=${source_id}&target_id=${target_id}&reset=yes&project_id=${project_id}">Reanalyze</a>]
<title>${source_file_name}: ${source_file_version_string} vs 
% if source_file_name != target_file_name:
	${target_file_name}: 
% endif
${target_file_version_string} Functions
</title>
	<table id="mainTable" class="FunctionmatchInfo">
		<thead>
		<tr>
			<th>Unpatched</th>

			% if show_detail > 1:
				<th>Address</th>
			% endif

			% if show_detail > 0:
				<th>Unidentified</th>
			% endif

			<th>Patched</th>
			% if show_detail > 1:
				<th>Address</th>
			% endif
		
			% if show_detail > 0:
				<th>Unidentified</th>
				<th>Matched</th>
				<th>Modifications</th>
			% endif

			<th>Security Implication Score</th>
		</tr>
		</thead>

		<tbody>
		% for function_match_info in function_match_infos:
			<tr>
				<td><a href="ShowBasicBlockMatchInfo?patch_id=${patch_id}&download_id=${download_id}&file_id=${file_id}&source_id=${source_id}&target_id=${target_id}&source_address=${function_match_info.source_address}&target_address=${function_match_info.target_address}" target="${source_id}+${target_id}+source_address=${function_match_info.source_address}+target_address=${function_match_info.target_address}">${function_match_info.source_function_name}</a></td>
				
				% if show_detail > 1:
					<td>${hex(function_match_info.source_address)[2:].upper()}</td>
				% endif

				% if show_detail > 0:
					<td>${function_match_info.non_match_count_for_the_source}</td>
				% endif

				<td><a href="ShowBasicBlockMatchInfo?patch_id=${patch_id}&download_id=${download_id}&file_id=${file_id}&source_id=${source_id}&target_id=${target_id}&source_address=${function_match_info.source_address}&target_address=${function_match_info.target_address}" target="${source_id}+${target_id}+source_address=${function_match_info.source_address}+target_address=${function_match_info.target_address}">${function_match_info.target_function_name}</a></td>
				
				% if show_detail > 1:
					<td>${hex(function_match_info.target_address)[2:].upper()}</td>
				% endif

				% if show_detail > 0:
					<td>${function_match_info.non_match_count_for_the_target}</td>
					<td>${function_match_info.match_count_for_the_source}</td>
					<td>${function_match_info.match_count_with_modificationfor_the_source}</td>
				% endif

				<td>${function_match_info.security_implications_score}</td>
			</tr>
		% endfor
		</tbody>
	</table>
</%def>
<html>
""" + HeadText + """

<body>
""" + MainMenu + """
<div id=Content>
<%self:layoutdata 
	source_file_name = "${source_file_name}"
	source_file_version_string = "${source_file_version_string}"
	target_file_name = "${target_file_name}"
	target_file_version_string = "${target_file_version_string}"
	show_detail="${show_detail}" 
	function_match_infos="${function_match_infos}" 
	args="col">\
</%self:layoutdata>
</div>
</body>
</html>"""

"""
str(function_match_info.block_type)
str(function_match_info.type)
str( function_match_info.match_rate )
"""
	
ComparisonTableTemplateText = """<%def name="layoutdata(source_file_name, 
	source_file_version_string, 
	target_file_name, 
	target_file_version_string, 
	source_function_name, 
	target_function_name, comparison_table,
	source_address,
	target_address)">

%if patch_name:
	<p><a href="/ShowMSPatchList">List</a>
	&gt;<a href="PatchInfo?id=${patch_id}">${patch_name}</a>
%endif

%if download_label:
	&gt;<a href="DownloadInfo?patch_id=${patch_id}&id=${download_id}">${download_label}</a>
%endif

%if file_name:
	&gt;<a href="FileInfo?patch_id=${patch_id}&download_id=${download_id}&id=${file_id}">${file_name}</a>
%endif

&gt;<a href="ShowFunctionMatchInfo?patch_id=${patch_id}&download_id=${download_id}&file_id=${file_id}&source_id=${source_id}&target_id=${target_id}">Functions</a>

<title>${source_file_name}: ${source_file_version_string}:${source_function_name} vs 
% if source_file_name != target_file_name:
	${target_file_name}: 
% endif
${target_file_version_string}:${target_function_name} Blocks</title>

<p><a href="ShowBasicBlockMatchInfo?patch_id=${patch_id}&download_id=${download_id}&file_id=${file_id}&source_id=${source_id}&target_id=${target_id}&source_address=${source_address}&target_address=${target_address}">
${source_file_name}: ${source_file_version_string}: ${source_function_name} vs 
% if source_file_name != target_file_name:
	${target_file_name}: 
% endif
${target_file_version_string}: ${target_function_name}
</a>

	<table class="Block">
		<tr>
			% if source_function_name:
				<td><b>Unpatched: ${source_function_name}<b></td>
			% else:
				<td><b>Unpatched</b></td>
			% endif

			% if target_function_name:
				<td><b>Patched: ${target_function_name}<b></td>
			% else:
				<td><b>Patched</b></td>
			% endif

		</tr>
	% for ( left_address, left_lines, right_address, right_lines, match_rate ) in comparison_table:
		% if left_address != 0 or right_address != 0:
			<tr>
				% if right_address == 0:
					<td class="UnidentifiedBlock">
				% else:
					% if match_rate == 100 or left_address == 0:
						<td class="MatchedBlock">
					% else:
						<td class="ModifiedBlock">
					% endif
				% endif

				% if left_address != 0:
					<b>[${hex(left_address)[2:].upper()}]</b>
				% endif
				<p>${left_lines}</td>
	
				% if left_address == 0:
					<td class="UnidentifiedBlock">
				% else:
					% if match_rate == 100 or right_address == 0:
						<td class="MatchedBlock">
					% else:
						<td class="ModifiedBlock">
					% endif
				% endif

				% if right_address != 0:
					<b>[${hex(right_address)[2:].upper()}]</b>
				% endif

				<p>${right_lines}</td>
			</tr>
		% endif
	% endfor
	</table>
</%def>
""" + HeadText + """
<div id=Content>
<%self:layoutdata 
	source_file_name = "${source_file_name}"
	source_file_version_string = "${source_file_version_string}"
	target_file_name = "${target_file_name}"
	target_file_version_string = "${target_file_version_string}"
	source_function_name="${source_function_name}" 
	target_function_name="${target_function_name}" 
	comparison_table="${comparison_table}" 
	source_address="${source_address}"
	target_address="${target_address}"
	args="col">\
</%self:layoutdata>
</div>
</div>
"""

MainBody = """
		<div id=Content>
		<%self:layoutdata args="col">\
		</%self:layoutdata>
		</div>
		</body>
		</html>"""

BodyHTML = """
<html>
""" + HeadText + """
<body>
""" + MainMenu + MainBody 

CloseButtonHTML = """<form method="post">
<input type="button" value="Close Window"
onclick="window.close()">
</form>"""

SyncIDAHTML="<html><body> Check your IDA %s </body></html>"
OpenInIDAHTML="<html><body> Check your IDA <p> Running %s %s <p>%s</body></html>"
