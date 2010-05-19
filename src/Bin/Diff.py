import sys
import DiffEngine

before_filename = sys.argv[1]
after_filename = sys.argv[2]

print 'Comparing',before_filename,after_filename
IDAClientManager = DiffEngine.IDAClientManager(1216)
OneClientManagerBefore=DiffEngine.OneIDAClientManager()
OneClientManagerBefore.Retrieve( before_filename )

OneClientManagerAfter=DiffEngine.OneIDAClientManager()
OneClientManagerAfter.Retrieve( after_filename )


DiffMachine = DiffEngine.DiffMachine( OneClientManagerBefore, OneClientManagerAfter )

DiffMachine.Analyze()
