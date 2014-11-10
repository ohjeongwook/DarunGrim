import sqlite3
from math import sqrt
import sys
import DarunGrimEngine
from pylab import *
import matplotlib.pyplot as plt
import numpy as np

def Draw( Values ):
	r = np.array( Values )
	fig = plt.figure()
	ax = fig.add_subplot(111)
	ax.plot( r )
	plt.show()

darungrim=DarunGrimEngine.DGFAnalyzer(sys.argv[1])

#FunctionMemberCounts = darungrim.RetrieveFunctionBasicBlockMap(1)
#Draw( FunctionMemberCounts )

#FunctionMemberCounts = darungrim.RetrieveFunctionBasicBlockMap(2)
#Draw( FunctionMemberCounts )

print 'GetFunctionMatchInfo', darungrim.GetFunctionMatchInfo()

"""
print 'Rep',len( darungrim.RetrievePatternAddresses(1,'%rep%' ) )
print 'Rep',len( darungrim.RetrievePatternAddresses(2,'%rep%' ) )
print 'Loop',len( darungrim.RetrievePatternAddresses(1,'%loop%' ) )
print 'Loop',len( darungrim.RetrievePatternAddresses(2,'%loop%' ) )
print 'xor',len( darungrim.RetrievePatternAddresses(1,'%xor%' ) )
print 'xor',len( darungrim.RetrievePatternAddresses(2,'%xor%' ) )
print 'ret',len( darungrim.RetrievePatternAddresses(1,'%ret%' ) )
print 'ret',len( darungrim.RetrievePatternAddresses(2,'%ret%' ) )
print 'mov',len( darungrim.RetrievePatternAddresses(1,'%mov%' ) )
print 'mov',len( darungrim.RetrievePatternAddresses(2,'%mov%' ) )
print 'lea',len( darungrim.RetrievePatternAddresses(1,'%lea%' ) )
print 'lea',len( darungrim.RetrievePatternAddresses(2,'%lea%' ) )
print 'cmp',len( darungrim.RetrievePatternAddresses(1,'%cmp%' ) )
print 'cmp',len( darungrim.RetrievePatternAddresses(2,'%cmp%' ) )
print 'test',len( darungrim.RetrievePatternAddresses(1,'%test%' ) )
print 'test',len( darungrim.RetrievePatternAddresses(2,'%test%' ) )
print 'push',len( darungrim.RetrievePatternAddresses(1,'%push%' ) )
print 'push',len( darungrim.RetrievePatternAddresses(2,'%push%' ) )
print 'Call DS:', len( darungrim.RetrievePatternAddresses(1,'%call%ds:%' ) )
print 'Call DS:', len( darungrim.RetrievePatternAddresses(2,'%call%ds:%' ) )

for (function_address,basic_block_address) in darungrim.RetrievePatternAddresses(1,'%jmp%[%]%' ):
	print hex(basic_block_address)
	print darungrim.RetrieveDisasmLines(1,basic_block_address)
	
print 'jmp',len( darungrim.RetrievePatternAddresses(1,'%jmp%[%]%' ) )
print 'jmp',len( darungrim.RetrievePatternAddresses(2,'%jmp%[%]%' ) )
print 'jmp',len( darungrim.RetrievePatternAddresses(1,'%jmp%' ) )
print 'jmp',len( darungrim.RetrievePatternAddresses(2,'%jmp%' ) )


print 'fingerprint',darungrim.RetrieveFingerprint(1)
print 'fingerprint',darungrim.RetrieveFingerprint(2)

print 'DisasmLines',darungrim.GetDisasmLinesLength(1)
print 'DisasmLines',darungrim.GetDisasmLinesLength(2)

(Address,Length) = darungrim.GetMaximumFingerPrintLength(1)
print 'MaximumFingerPrintLength', hex(Address), Length
(Address,Length) = darungrim.GetMaximumFingerPrintLength(2)
print 'MaximumFingerPrintLength', hex(Address), Length
"""

"""
hist( FunctionMemberCounts )
draw()
savefig('c:\mat\hist2.png',dpi=300)
close()
"""

"""
FullMatchedBlocksCount=darungrim.GetFullMatchedBlocksCount()

MatchMapCount=darungrim.GetMatchMapCount()

UnidentifiedBlocksCount_1=darungrim.GetUnidentifiedBlocksCount(1)
UnidentifiedBlocksCount_2=darungrim.GetUnidentifiedBlocksCount(2)

WholeBlocksCount=darungrim.GetOneLocationInfoCount(1)+darungrim.GetOneLocationInfoCount(2)
IdentifiedMatchMapCount=WholeBlocksCount-UnidentifiedBlocksCount_1-UnidentifiedBlocksCount_2
MatchRate=(IdentifiedMatchMapCount*100/WholeBlocksCount)
FullMatchRate=(FullMatchedBlocksCount*2*100/WholeBlocksCount)

print 'GetFullMatchedBlocksCount:',FullMatchedBlocksCount
print 'GetMatchMapCount:',MatchMapCount
print 'GetUnidentifiedBlocksCount(1):',UnidentifiedBlocksCount_1
print 'GetUnidentifiedBlocksCount(2):',UnidentifiedBlocksCount_2
print 'MatchRate',IdentifiedMatchMapCount,'/',WholeBlocksCount,'=',MatchRate,'%'
print 'FullMatchRate',FullMatchedBlocksCount*2,'/',WholeBlocksCount,'=',FullMatchRate,'%'
"""