import os
import mechanize
from BeautifulSoup import BeautifulSoup
import PatchDatabaseWrapper
import datetime

class PatchDownloader:
	DebugLevel = 3
	ShowErrorMessage = True
	def __init__( self, download_folder, databasename = 'test.db' ):
		self.DownloadFolder = download_folder
		if not os.path.isdir( self.DownloadFolder ):
			os.makedirs( self.DownloadFolder )
		self.Database = PatchDatabaseWrapper.Database( databasename )
		self.BR = mechanize.Browser()

	def DownloadFileByLink( self, link ):
		family_id = self.GetFamilyID( link )
		if family_id:
			return self.DownloadFileByFamilyID( family_id )
		return None

	def DownloadFileByFamilyID( self, family_id ):
		return self.DownloadFileByConfirmationLink( 'http://www.microsoft.com/downloads/en/confirmation.aspx?familyId=' + family_id + '&displayLang=en' )
		
	def DownloadFileByConfirmationLink( self, link ):
		try:
			data = self.BR.open( link ).get_data()
		except:
			return []

		if self.DebugLevel > 3:
			print '='*80
			print link
			print data

		files = []
		soup = BeautifulSoup( data )
		for anchor in soup.findAll( "a" ):
			for name, download_link in anchor.attrs:
				if anchor.text == 'Start download' and name =='href':
					print  'Found Start download'
					filename = download_link[download_link.rfind("/")+1:]
					filename = os.path.join( self.DownloadFolder, filename )
					if self.DebugLevel > -3:
						print '\t\t',download_link,'->',filename

					try:
						if not os.path.isfile( filename ):
							data = self.BR.open( download_link ).get_data()

							if data and len( data ) > 0:
								fd = open( filename, "wb" )
								fd.write( data )
								fd.close()
						files.append( filename )
					except:
						print 'Failed to download', download_link
		return files

	def GetFamilyID( self, link ):
		family_id = None
		if link:
			pos = link.lower().find("familyid=")
			if  pos >=0:
				family_id = link[pos+len( 'familyid=' ):]
				ampersand_pos = family_id.find("&")
				if ampersand_pos >= 0:
					family_id = family_id[:ampersand_pos]

				if self.DebugLevel > 3:
					print '\t',link
					print '\t',family_id
					print ''
		return family_id

	def DownloadMSPatch( self, Year, PatchNumber, download_patch_files = False ):
		url = 'http://www.microsoft.com/technet/security/Bulletin/MS%.2d-%.3d.mspx' % ( Year, PatchNumber )
		try:
			data = self.BR.open( url ).get_data()
		except:
			if self.ShowErrorMessage:
				print 'Downloading Failed'
			return None

		soup = BeautifulSoup( data )

		title = ''
		for h1_tag in soup.find( "h1" ):
			title = h1_tag.string

		for h2_tag in soup.find( "h2" ):
			title += h2_tag.string

		patch_info = {}
		patch_info['label'] = 'MS%.2d-%.3d' % ( Year, PatchNumber )
		patch_info['url'] = url
		patch_info['title'] = title

		#Retrieve CVEs
		CVEs=[]
		for h2_tag in soup.findAll( "h2" ):
			if h2_tag.string == 'Vulnerability Information':
				current_tag = h2_tag.nextSibling
				while 1:
					if current_tag.name == 'h2':
						break
					for h3_tag in current_tag.findAll('h3'):
						cve_pos = h3_tag.string.find('CVE-')
						if cve_pos >= 0:
							if self.DebugLevel > 3:
								print h3_tag.string
							cve_str=h3_tag.string[cve_pos:cve_pos+13]
							CVEs.append( ( cve_str, h3_tag.string ) )
					current_tag = current_tag.nextSibling

		for h3_tag in soup.findAll( "h3" ):
			if h3_tag.string == 'Vulnerability Details':
				#print 'h3_tag',h3_tag.string
				pass

		for h4_tag in soup.findAll( "h4" ):
			if h4_tag.string:
				cve_pos = h4_tag.string.find('CVE-')
				can_pos = h4_tag.string.find('CAN-')

				if  cve_pos >= 0:
					cve_str=h4_tag.string[cve_pos:cve_pos+13]
					CVEs.append( ( cve_str, h4_tag.string ) )

				if can_pos >= 0:
					cve_str=h4_tag.string[can_pos:can_pos+13]
					CVEs.append( ( cve_str, h4_tag.string ) )

		patch_info['CVE'] = CVEs
		patch_info['HtmlData'] = data

		patch_data = []
		for p_tag in soup.findAll( "p" ):
			if p_tag.text == 'Affected Software':
				table_tag = p_tag.nextSibling

				tr_members = []
				if table_tag:
					for tr in table_tag.findAll( "tr" ):
						if self.DebugLevel > 3:
							print "=" * 80
						td_members = []
						for td in tr.findAll( "td" ):
							td_str = ''
							url_str = ''
							if td.string:
								td_str = td.string
							for tag in td.findAll(True):
								if tag.name == 'a':
									for name, link in tag.attrs:
										if name == 'href':
											url_str = link
								if tag.string:
									td_str += tag.string
							if self.DebugLevel > 3:
								print '>',td_str
							
							td_member = {}
							td_member['text'] = td_str
							td_member['url'] = url_str
							td_members.append( td_member )
						if self.DebugLevel > 3:
							print ""
						tr_members.append( td_members )

				for td_members in tr_members[1:]:
					column = 0 
					td_member_hash = {}
					for td_member in td_members:
						link = None
						if td_member.has_key( 'url' ):
							link = td_member['url']
						#print td_member['text'] + "(" + link + ")", 
						column_text = ''
						if len( tr_members[0] ) > column:
							column_text = tr_members[0][column]['text']
					
						family_id = self.GetFamilyID( link )
						if download_patch_files:	
							if family_id:
								td_member['files'] = self.DownloadFileByFamilyID( family_id )
						elif family_id:
							td_member['files'] = ( family_id )
						td_member_hash[ column_text ] = td_member
						column += 1

					if self.DebugLevel > 3:
						print td_member_hash
						print ''

					patch_data.append( td_member_hash )

			elif p_tag.text == 'Affected Software:' or p_tag.text == 'Affected Components:':
				table_tag = p_tag.nextSibling
				for td_tag in table_tag.findAll('td'):
					td_member_hash = {}
					td_member = {}

					for p_tag in td_tag.findAll('p'):
						if self.DebugLevel > 3:
							print 'p_tag=',p_tag.contents[0]
						td_member['text'] = str( p_tag.contents[0] )

					for a_tag in td_tag.findAll('a'):					
						for name, link in a_tag.attrs:
							if name == 'href':
								td_member['url'] = link
								family_id = self.GetFamilyID( link )
								if download_patch_files:	
									if self.DebugLevel > 3:
										print link
										print family_id
									if family_id:
										td_member['files'] = self.DownloadFileByFamilyID( family_id )
								elif family_id:
									td_member['files'] = ( family_id )

						td_member_hash['Data'] = td_member
						td_member_hash['Maximum Security Impact']={}
						td_member_hash['Maximum Security Impact']['text'] = ''
						td_member_hash['Aggregate Severity Rating']={}
						td_member_hash['Aggregate Severity Rating']['text'] = ''
					patch_data.append( td_member_hash )

		return ( patch_info, patch_data )

	def DownloadMSPatchAndIndex( self, Year, PatchNumber, download_patch_files = False ):
		name = 'MS%.2d-%.3d' % ( Year, PatchNumber )
		if self.Database.GetPatch( name ):
			return ( {},{} )

		print 'Downloading',name
		ret = self.DownloadMSPatch( Year, PatchNumber, download_patch_files )

		if not ret:
			if self.ShowErrorMessage:
				print 'Nothing to do'
			return ret

		(patch_info, patch_data) = ret
		
		patch = self.Database.AddPatch( patch_info['label'], patch_info['title'], patch_info['url'], patch_info['HtmlData'] )

		for (cve_str, name) in patch_info['CVE']:
			self.Database.AddCVE( patch, cve_str, name )

		for td_member_hash in patch_data:
			for ( column_text, td_member ) in td_member_hash.items():
				if td_member.has_key( 'files' ):
					if self.DebugLevel > 3:
						for ( name, data ) in td_member.items():
							print '\t', name, data
						
					if td_member_hash.has_key( 'Operating System' ):
						operating_system = td_member_hash['Operating System']['text']
					else:
						operating_system = td_member['text']

					if self.DebugLevel > 3:
						print operating_system 
						print td_member['text']
						print td_member['url']
						print td_member['files'][0]
						if td_member_hash.has_key('Maximum Security Impact'):
							print td_member_hash['Maximum Security Impact']['text']
						if td_member_hash.has_key('Aggregate Severity Rating'):
							print td_member_hash['Aggregate Severity Rating']['text']

					bulletins_replaced = ""
					if td_member_hash.has_key( 'Bulletins Replaced by This Update' ):
						bulletins_replaced = td_member_hash['Bulletins Replaced by This Update']['text'] 
					if td_member_hash.has_key( 'Bulletins Replaced by this Update' ):
						bulletins_replaced = td_member_hash['Bulletins Replaced by this Update']['text'] 

					maximum_security_impact = ''
					
					if td_member_hash.has_key('Maximum Security Impact') and td_member_hash['Maximum Security Impact'].has_key('text'):
						maximum_security_impact = td_member_hash['Maximum Security Impact']['text']
					
					aggregate_severity_rating = ''
					if td_member_hash.has_key('Aggregate Severity Rating') and td_member_hash['Aggregate Severity Rating'].has_key('text'):
						aggregate_severity_rating = td_member_hash['Aggregate Severity Rating']['text']

					filename = ""
					if td_member.has_key( 'files' ) and len(td_member['files']) > 0:
						filename = td_member['files'][0]

					if self.DebugLevel > 2:
						print 'Calling AddDownload', patch, filename
					self.Database.AddDownload( 
						patch, 
						operating_system, 
						td_member['text'], 
						td_member['url'], 
						filename,
						maximum_security_impact,
						aggregate_severity_rating,
						bulletins_replaced 
					)

		if not self.Database.Commit():
			print 'Failed Downloading',name
		return ret

	def DownloadPatches( self, start_year, start_number, end_year, end_number ):
		for year in range( start_year, end_year+1 ):
			current_start_number = 1
			current_end_number = 999
			if year == start_year:
				current_start_number = start_number
			elif year == end_year:
				current_end_number = end_number
			
			for patch_number in range( current_start_number, current_end_number):
				print 'Checking for MS%.2d-%.3d' % ( year, patch_number )
				ret = self.DownloadMSPatchAndIndex( year, patch_number )
				if ret == None:
					break
		return

	def DownloadCurrentYearPatches( self ):
		now = datetime.datetime.now()
		year = now.year - 2000
		return self.DownloadPatches( year, 1, year, 999 )

if __name__ == '__main__':
	patch_downloader = PatchDownloader( "Patches" )

	#patch_downloader.DownloadMSPatchAndIndex( 9, 18 )
	#patch_downloader.DownloadMSPatchAndIndex( 8, 1 )
	#patch_downloader.DownloadMSPatchAndIndex( 10, 31 )
	patch_downloader.DownloadCurrentYearPatches()

