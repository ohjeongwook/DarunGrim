# setup.py
import pygtk
pygtk.require('2.0')
import gtk
import gtk,gobject,cairo
from distutils.core import setup
import py2exe
import glob
import sys
sys.path.append(r'\mat\Projects\ResearchTools\Graphics\GraphVizInterface\Src')
sys.path.append(r"..\bin")

opts = {
    "py2exe": {
        "packages": "encodings",
        "includes": "pango,atk,gobject,tempfile,new,gtk,pangocairo,cairo,pygtk",
        "dll_excludes": [
        "iconv.dll","intl.dll","libatk-1.0-0.dll",
        "libgdk_pixbuf-2.0-0.dll","libgdk-win32-2.0-0.dll",
        "libglib-2.0-0.dll","libgmodule-2.0-0.dll",
        "libgobject-2.0-0.dll","libgthread-2.0-0.dll",
        "libgtk-win32-2.0-0.dll","libpango-1.0-0.dll",
        "libpangowin32-1.0-0.dll"],
        }
    }

setup(
    name = "DiffBrowser",
    description = "A nice GUI interface for those with GiantDisc jukebox systems.",
    version = "0.61",
    windows = [
        {"script": "DiffBrowser.py"
        }
    ],
    options=opts
)

