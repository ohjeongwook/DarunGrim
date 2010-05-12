import os
import mechanize
from BeautifulSoup import BeautifulSoup

class PatchDownloader:
	DebugLevel = 0
	def __init__( self, DownloadFolder ):
		self.DownloadFolder = DownloadFolder

	def DownloadFileByFamilyID( self, br, family_id ):
		link = 'http://www.microsoft.com/downloads/en/confirmation.aspx?familyId=' + family_id + '&displayLang=en'
		
		try:
			data = br.open( link ).get_data()
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
					filename = download_link[download_link.rfind("/")+1:]
					filename = os.path.join( self.DownloadFolder, filename )
					print '\t\t',download_link,'->',filename

					try:
						data = br.open( download_link ).get_data()

						fd = open( filename, "wb" )
						fd.write( data )
						fd.close()
						files.append( filename )
					except:
						print 'Failed to download', download_link

		return files

	def DownloadMSPatch( self, Year, PatchNumber ):
		url = 'http://www.microsoft.com/technet/security/Bulletin/MS%.2d-%.3d.mspx' % ( Year, PatchNumber )
		print url
		br = mechanize.Browser()
		try:
			data = br.open( url ).get_data()
		except:
			return None

		soup = BeautifulSoup( data )

		files = []
		for anchor in soup.findAll( "a" ):
			for name, link in anchor.attrs:
				print name,link
				pos = link.find("familyid=")
				if  pos < 0:
					pos = link.find("FamilyId=")

				if  pos >=0:
					family_id = link[pos+len( 'familyid=' ):]
					ampersand_pos = family_id.find("&")
					if ampersand_pos >= 0:
						family_id = family_id[:ampersand_pos]

					if self.DebugLevel > -1:
						print anchor.text
						print '\t',link
						print '\t',family_id
						print ''
						
					print '\t',anchor.text
					files += self.DownloadFileByFamilyID( br, family_id )
		return files

if __name__ == '__main__':
	patch_downloader = PatchDownloader( "Patches" )

	for Year in range(9,10):
		for PatchNumber in range(32, 33):
			files = patch_downloader.DownloadMSPatch( Year, PatchNumber )
			if files == None:
				break
			print files
		
