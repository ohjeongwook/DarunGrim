# -*- mode: python -*-
a = Analysis(['DarunGrim.py'],
             pathex=['C:\\mat\\Src\\DarunGrim\\Src\\Scripts'],
             hiddenimports=[],
             hookspath=None,
             runtime_hooks=None)
pyz = PYZ(a.pure)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='DarunGrim.exe',
          debug=False,
          strip=None,
          upx=True,
          console=False,
		  icon='DarunGrim.ico' )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=None,
               upx=True,
               name='DarunGrim')
