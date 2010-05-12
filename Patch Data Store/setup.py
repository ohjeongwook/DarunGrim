from distutils.core import setup, Extension

setup (name = "win32ver", 
	version = "1.0",
	maintainer = "Jeong Wook Oh",
	maintainer_email = "oh.jeongwook@gmail.com",
	description = "Win32 Version Information Retriever",
	
	ext_modules = [Extension('win32ver', 
			sources = ['win32ver.cpp'], 
			libraries = ['version'] ) ]
)
