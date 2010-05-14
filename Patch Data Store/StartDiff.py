from FileStore import *
import Indexer

DatabaseName = 'test.db'
Database = Indexer.Database( DatabaseName )

patches_for_distro = {}
for database in Database.GetFileByFileInfo( 'netapi32.dll' ):
	ret = database.version_string.split( ' ' )
	distro = ''
	if len( ret ) == 1:
		version = ret[0]
	elif len( ret ) == 2:
		( version, distro ) = ret
	
	dot_pos = distro.find(".")
	if dot_pos >= 0:
		distro = distro[:dot_pos]
	distro = distro[1:]
	#print distro, ":\t\t", version
	if not patches_for_distro.has_key( distro ):
		patches_for_distro[ distro ] = []
	patches_for_distro[ distro ].append( version )


distros = patches_for_distro.keys()
distros.sort()
for distro in distros:
	print distro
	versions = patches_for_distro [distro]
	for version in versions:
		print '\t',version

