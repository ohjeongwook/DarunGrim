## {{{ http://code.activestate.com/recipes/325823/ (r1)
#!/usr/bin/env python
"""\
SVG.py - Construct/display SVG scenes.

The following code is a lightweight wrapper around SVG files. The metaphor
is to construct a scene, add objects to it, and then write it to a file
to display it.

This program uses ImageMagick to display the SVG files. ImageMagick also 
does a remarkable job of converting SVG files into other formats.
"""

import os
display_prog = 'display' # Command to execute to display images.
	  
class Scene:
	def __init__(self,name="svg",height=400,width=400):
		self.name = name
		self.items = []
		self.height = height
		self.width = width
		return

	def add(self,item): self.items.append(item)

	def strarray(self):
		var = ["<svg xmlns=\"http://www.w3.org/2000/svg\"\
				xmlns:xlink=\"http://www.w3.org/1999/xlink\"\
				version=\"1.1\"\
				baseProfile=\"full\"\
				height=\"%d\" width=\"%d\" >\n" % (self.height,self.width),
			   " <g style=\"fill-opacity:1.0; stroke:black;\n",
			   "  stroke-width:1;\">\n"]
		for item in self.items: var += item.strarray()			
		var += [" </g>\n</svg>\n"]
		return var

	def write_svg(self,filename=None):
		if filename:
			self.svgname = filename
		else:
			self.svgname = self.name + ".svg"
		file = open(self.svgname,'w')
		file.writelines(self.strarray())
		file.close()
		return

	def display(self,prog=display_prog):
		os.system("%s %s" % (prog,self.svgname))
		return		
		

class Line:
	def __init__(self,start,end):
		self.start = start #xy tuple
		self.end = end	 #xy tuple
		return

	def strarray(self):
		return ["  <line x1=\"%d\" y1=\"%d\" x2=\"%d\" y2=\"%d\" />\n" %\
				(self.start[0],self.start[1],self.end[0],self.end[1])]


class Circle:
	def __init__(self,center,radius,color):
		self.center = center #xy tuple
		self.radius = radius #xy tuple
		self.color = color   #rgb tuple in range(0,256)
		return

	def strarray(self):
		return ["  <circle cx=\"%d\" cy=\"%d\" r=\"%d\"\n" %\
				(self.center[0],self.center[1],self.radius),
				"	style=\"fill:%s;\"  />\n" % colorstr(self.color)]

class Rectangle:
	def __init__(self,origin,height,width,color):
		self.origin = origin
		self.height = height
		self.width = width
		self.color = color
		return

	def strarray(self):
		return ["  <rect x=\"%d\" y=\"%d\" height=\"%d\"\n" %\
				(self.origin[0],self.origin[1],self.height),
				"	width=\"%d\" style=\"fill:%s;\" />\n" %\
				(self.width,colorstr(self.color))]

class Text:
	def __init__(self,origin,text,size=24,margin=1):
		self.origin = origin
		self.text = text
		self.size = size
		self.margin = margin
		return

	def strarray(self):
		data = ''
		x = self.origin[0]
		y = self.origin[1]
		for line in self.text.split('\n'):				
			data += "<tspan x=\"%d\" y=\"%d\"> %s </tspan>" % ( x, y, line )
			y += self.size + self.margin

		return ["<text x=\"%d\" y=\"%d\" font-size=\"%d\" width=\"40\">\n" %\
				(self.origin[0],self.origin[1],self.size),
				"   %s\n" % ( data ), 
				"  </text>\n"]

def colorstr(rgb): return "#%x%x%x" % (rgb[0]/16,rgb[1]/16,rgb[2]/16)

class Blocks:
	def __init__( self, scene, x, y, block_data ):
		self.font_size = 14
		self.margin = 2
		self.x = x
		self.y = y
		self.scene = scene
		self.width = 0
		self.Coordinates={}

		keys = block_data.keys()
		keys.sort()
		for key in keys:
			self.Append( key, block_data[key] )

	def GetSize( self, data ):
		lines = data.split('\n')
		
		width = 0
		for line in lines:
			if width < 3 * len(line):
				width = 3 * len(line)

		height = len( lines ) * ( self.font_size + self.margin )
		return ( width, height )

	def Append(self, key, data ):
		( width, height ) = self.GetSize( data )
		if self.width < width:
			self.width = width
		self.Coordinates[key] = ( self.x, self.y, width, height )

		self.scene.add( Text( ( self.x, self.y ), data, self.font_size, self.margin ))
		self.y += height

	def GetLen( self ):
		return len( self.Coordinates )

	def GetCoords( self, key ):
		return self.Coordinates[ key ]

class DisasmComparisonTable:
	def __init__( self, scene, LeftData, RightData, Map ):
		self.scene = scene

		self.LeftBlocks=Blocks( scene, 50, 50, LeftData  )
		self.RightBlocks=Blocks( scene, 350, 50, RightData )

		for Src in Map.keys():
			self.Link( Src, Map[ Src ] )

	def Link( self, key1, key2 ):
		(x1,y1,w1,h1) = self.LeftBlocks.GetCoords( key1 )
		px1 = x1 + w1
		py1 = y1 + h1/2

		(x2,y2,w2,h2) = self.RightBlocks.GetCoords( key2 )
		px2 = x2
		py2 = y2 + h2/2
				
		self.scene.add(Line((px1,py1),(px2,py2)))

if __name__ == '__main__':
	TestData = {0x2080148B: """
	sub_2080148B	proc near			   
	 push	ebp
	 lea	 ebp, [esp-78h]
	 sub	 esp, 98h
	 mov	 eax, dword_210896C0
	 xor	 eax, ebp
	 mov	 [ebp+78h+var_4], eax
	 push	esi
	 mov	 esi, ecx
	 call	sub_2080153A
	 mov	 eax, offset __ImageBase
	 push	94h			 ; Size
	 mov	 [esi+8], eax
	 mov	 [esi+4], eax
	 lea	 eax, [ebp+78h+Dst]
	 push	0			   ; Val
	 push	eax			 ; Dst
	 mov	 dword ptr [esi], 3Ch
	 mov	 byte ptr [esi+0Ch], 0
	 call	memset
	 add	 esp, 0Ch
	 lea	 eax, [ebp+78h+Dst]
	 push	eax			 ; lpVersionInformation
	 mov	 [ebp+78h+Dst], 94h
	 call	ds:GetVersionExA
	 cmp	 [ebp+78h+var_88], 2
	 jnz	 short loc_208014EF
	 cmp	 [ebp+78h+var_94], 5
	 jb	  short loc_20801507
	 jmp	 short loc_20801503

	""",

	0x208014EF:
	"""
	loc_208014EF:						   
	 cmp	 [ebp+78h+var_88], 1
	 jnz	 short loc_20801507
	 cmp	 [ebp+78h+var_94], 4
	 ja	  short loc_20801503
	 jnz	 short loc_20801507
	 cmp	 [ebp+78h+var_90], 0
	 jbe	 short loc_20801507
	""",

	0x20801503:
	"""
	loc_20801503:						   
	 mov	 byte ptr [esi+0Ch], 1
	""",

	0x20801507:
	"""
	loc_20801507:						   
							 
	 lea	 ecx, [esi+18h]
	 mov	 dword ptr [esi+10h], 800h
	 mov	 dword ptr [esi+14h], offset unk_20DDD154
	 call	sub_20801440
	 test	eax, eax
	 jge	 short loc_20801528
	 mov	 byte_210897D8, 1
	""",

	0x20801528:
	"""
	loc_20801528:						   
	 mov	 ecx, [ebp+78h+var_4]
	 mov	 eax, esi
	 xor	 ecx, ebp
	 pop	 esi
	 call	sub_20801554
	 add	 ebp, 78h
	 leave
	 retn
	"""}
	
	def test():
		Map = { 0x2080148B:0x208014EF,
			0x208014EF:0x208014EF,
			0x20801503:0x20801503,
			0x20801507:0x20801528,
			0x20801528:0x20801507 }

		scene = Scene('test', 1000, 1000 )	
		DisasmComparisonTable( scene, TestData, TestData, Map )
		scene.write_svg()
		return
	test()	
