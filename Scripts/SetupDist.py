from distutils.core import setup
import py2exe

setup(
	console=[ {"script" : 'DarunGrim3Server.py' } ],
	options =  {
		"py2exe": {
			"includes": "mechanize",
			"packages": ["sqlalchemy.dialects.sqlite", "mako.cache"],
			"dist_dir": "bin",
		}
	}
)
 
