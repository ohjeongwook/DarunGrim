import sys

UNKNOWN_BLOCK=0
FUNCTION_BLOCK=1
import DiffEngine
IDAClientManager=DiffEngine.IDAClientManager(1216)
IDAClientManager.CreateOneIDAClientManagers()
DiffMachine=IDAClientManager.InitializeDiffMachine()
DiffMachine.Analyze()
#DiffMachine.ShowResultsOnIDA()
match_info_size=DiffMachine.GetMatchInfoSize()
for i in range(0,match_info_size):
	match_info=DiffMachine.GetMatchInfo(i)
	if match_info.block_type==FUNCTION_BLOCK:
		print match_info.name,match_info.match_name
		#print match_info.addr,match_info.end_addr,match_info.block_type,match_info.match_rate,match_info.name,match_info.type,match_info.match_addr,match_info.match_name,match_info.first_found_match,match_info.first_not_found_match,match_info.second_found_match,match_info.second_not_found_match,


#IDAClientManager.IDACommandProcessor();