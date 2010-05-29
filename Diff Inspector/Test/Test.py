import sqlite3
from math import sqrt
import sys
import DarunGrim
#from pylab import *
#import matplotlib.pyplot as plt
#import numpy as np

import SVG

def Draw( Values ):
	r = np.array( Values )
	fig = plt.figure()
	ax = fig.add_subplot(111)
	ax.plot( r )
	plt.show()

darungrim=DarunGrim.DGFAnalyzer(sys.argv[1])

def WriteSVG( FunctionAddresses, OutputFile ):
	( DisasmLineHash, MatchMap ) = darungrim.GetMatchedFunctionMemberList( FunctionAddresses ) 
	scene = SVG.Scene(OutputFile, 25000, 25000 )	
	SVG.DisasmComparisonTable( scene, DisasmLineHash[0], DisasmLineHash[1], MatchMap )
	scene.write_svg()
	
def GetDisasmComparisonTable( LeftData, RightData, Map ):
	DebugLevel = 0
	left_addresses = LeftData.keys()
	left_addresses.sort()

	right_addresses = RightData.keys()
	right_addresses.sort()
	
	right_addressesIndex={}	
	index = 0
	for address in right_addresses:
		right_addressesIndex[address] = index
		index += 1
	
	DisasmTable={}
	Checkedright_addresses={}
	left_address_index = 0
	for left_address in left_addresses:
		right_address_index = None
		maximum_index = left_address_index
		if Map.has_key( left_address ):
			right_address = Map[ left_address ]
			Checkedright_addresses[ right_address ] = 1
			
			if right_addressesIndex.has_key( right_address ):
				right_address_index = right_addressesIndex[right_address]
				if DebugLevel > 2:
					print left_address_index, right_address_index
				
				if left_address_index > right_address_index:
					maximum_index = left_address_index
				elif left_address_index < right_address_index:
					maximum_index = right_address_index

		while DisasmTable.has_key( maximum_index ):
			maximum_index += 1

		DisasmTable[ maximum_index ] = ( left_address_index, right_address_index )
		left_address_index += 1

	for right_address in right_addressesIndex:
		if not Checkedright_addresses.has_key( right_address ):
			right_address_index = right_addressesIndex[right_address]
			
			NewDisasmTable = {}
			if DisasmTable.has_key( right_address_index ):
				for index in DisasmTable.keys():
					if index >= right_address_index:
						NewDisasmTable[ index + 1 ] = DisasmTable[ index ]
					else:
						NewDisasmTable[ index ] = DisasmTable[ index ]
				NewDisasmTable[right_address_index] = ( None, right_address_index )
				DisasmTable = NewDisasmTable
			else:
				DisasmTable[right_address_index] = ( None, right_address_index )

	if DebugLevel > 2:
		print DisasmTable
	indexes = DisasmTable.keys()
	indexes.sort()

	disasm_lines=[]

	for index in indexes:
		( left_address_index, right_address_index ) = DisasmTable[index]

		left_address = 0
		right_address = 0
		if left_address_index:
			left_address = left_addresses[ left_address_index ]
			
		if right_address_index:
			right_address = right_addresses[ right_address_index ]

		disasm_lines.append( ( hex(left_address)+":", hex(right_address)+":" ) )
		if DebugLevel > 2:
			print index, ':', left_address_index, hex(left_address), right_address_index, hex(right_address)

		left_lines=()
		right_lines=()

		if LeftData.has_key(left_address):
			left_lines = LeftData[ left_address ].split('\n')

		if RightData.has_key(right_address):
			right_lines = RightData[ right_address ].split('\n')
	
		if DebugLevel > 2:
			print 'Split Lines'
			print left_lines, right_lines

		i = 0
		while 1:
			left_line = ''
			if len(left_lines) > i:
				left_line = left_lines[i]
			right_line = ''
			if len(right_lines) > i:
				right_line = right_lines[i]

			if left_line=='' and right_line=='':
				break

			disasm_lines.append( (left_line, right_line) )
			i += 1
		disasm_lines.append( ( "", "" ) )

	return disasm_lines

def DumpComparisionTextTable( FunctionAddresses, OutputFile ):
	( DisasmLineHash, MatchMap ) = darungrim.GetMatchedFunctionMemberList( FunctionAddresses ) 

	#print 'GetDisasmComparisonTable',hex(FunctionAddresses[0]),hex(FunctionAddresses[1])
	disasm_lines = GetDisasmComparisonTable( DisasmLineHash[0], DisasmLineHash[1], MatchMap )
	
	disasm_comparion_table = ''
	maximum_left_line_length = 0
	for (left_line, right_line) in disasm_lines:
		if len( left_line ) > maximum_left_line_length:
			maximum_left_line_length = len( left_line )
	
	maximum_left_line_length += 10
	for (left_line, right_line) in disasm_lines:
		space_len = maximum_left_line_length - len( left_line )
		disasm_comparion_table += left_line + " " * space_len + right_line + '\n'

	fd = open( OutputFile, "w" )
	fd.write( disasm_comparion_table )
	fd.close()

Options = {"matched":1,"modified":1,"unidentified":1}
Options = {"matched":0,"modified":1,"unidentified":0}

print 'Count',darungrim.GetMatchedFunctionList( Options, None, None, True )
matched_function_list = darungrim.GetMatchedFunctionList( Options, 1, 100 )

for match_function_info in matched_function_list:
	print match_function_info["TheSourceFunctionName"],hex(match_function_info["TheSourceAddress"]),match_function_info["TheTargetFunctionName"],hex(match_function_info["TheTargetAddress"]),match_function_info["MatchRate"]
	TheSourceAddress = match_function_info["TheSourceAddress"]
	TheTargetAddress = match_function_info["TheTargetAddress"]
	#WriteSVG( ( TheSourceAddress, TheTargetAddress ) , hex(TheSourceAddress) + '-' + hex(TheTargetAddress) )
	DumpComparisionTextTable( ( TheSourceAddress, TheTargetAddress ) , "Output/" + hex(TheSourceAddress) + '-' + hex(TheTargetAddress) + ".txt" )

