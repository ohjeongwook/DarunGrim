#include "MatchResults.h"
#include "Log.h"

MatchResults::MatchResults() :pDumpAddressChecker(NULL)
{
}

void MatchResults::SetDumpAddressChecker(DumpAddressChecker* p_dump_address_checker)
{
	pDumpAddressChecker = p_dump_address_checker;
}

void MatchResults::Clear()
{
	MatchMap.clear();
	ReverseAddressMap.clear();
}

void MatchResults::EraseSource(vector <va_t>& addresses, va_t address, va_t source, va_t target)
{
	for (multimap <va_t, MatchData>::iterator it = MatchMap.find(address); it != MatchMap.end() && it->first == address; it++)
	{
		if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(it->first, it->second.Addresses[1]))
		{
			LogMessage(0, __FUNCTION__, "%s %X-%X\n", __FUNCTION__, it->first, it->second.Addresses[1]);
			LogMessage(0, __FUNCTION__, "\tOriginal erase target: %X-%X\n", source, target);
		}
		addresses.push_back(it->second.Addresses[1]);
		it = MatchMap.erase(it);
	}
}

void MatchResults::EraseTarget(vector <va_t>& addresses, va_t address, va_t source, va_t target)
{
	for (multimap <va_t, va_t>::iterator it = ReverseAddressMap.find(address); it != ReverseAddressMap.end() && it->first == address; it++)
	{
		if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(it->second, it->first))
		{
			LogMessage(0, __FUNCTION__, "%s %X-%X\n", __FUNCTION__, it->second, it->first);
			LogMessage(0, __FUNCTION__, "\tOriginal erase target: %X-%X\n", source, target);
		}
		addresses.push_back(it->second);
		it = ReverseAddressMap.erase(it);
	}
}

void MatchResults::Erase(va_t source, va_t target)
{
	if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(source, target))
		LogMessage(0, __FUNCTION__, "%s -> %X-%X\n", __FUNCTION__, source, target);

	vector <va_t> sources;
	vector <va_t> targets;

	sources.push_back(source);
	targets.push_back(target);

	while (sources.size() > 0)
	{
		for (vector<va_t>::iterator it = sources.begin(); it != sources.end(); it++)
		{
			EraseSource(targets, *it, source, target);
		}
		sources.clear();

		for (vector <va_t>::iterator it = targets.begin(); it != targets.end(); it++)
		{
			EraseTarget(sources, *it, source, target);
		}
		targets.clear();
	}
}

multimap <va_t, MatchData>::iterator MatchResults::Erase(multimap <va_t, MatchData>::iterator match_map_iter)
{
	if (match_map_iter != MatchMap.end())
	{
		if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1]))
			LogMessage(0, __FUNCTION__, "%s %X-%X\n", __FUNCTION__, match_map_iter->second.Addresses[0], match_map_iter->second.Addresses[1]);

		for (
			multimap <va_t, va_t>::iterator it = ReverseAddressMap.find(match_map_iter->second.Addresses[1]);
			it != ReverseAddressMap.end() && it->first == match_map_iter->second.Addresses[1];
			it++)
		{
			if (it->second == match_map_iter->first)
				it = ReverseAddressMap.erase(it);
		}
		match_map_iter = MatchMap.erase(match_map_iter);
	}
	return match_map_iter;
}

void MatchResults::AddMatchData(MatchData& match_data, const char* debug_str)
{
	if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
		LogMessage(0, __FUNCTION__, "%s %s [%d] %X-%X: %d%%\n", __FUNCTION__, debug_str, match_data.Type, match_data.Addresses[0], match_data.Addresses[1], match_data.MatchRate);

	va_t src = match_data.Addresses[0];
	va_t target = match_data.Addresses[1];
	bool add = true;
	for (multimap <va_t, MatchData>::iterator it = MatchMap.find(src); it != MatchMap.end() && it->first == src; it++)
	{
		if ((*it).second.MatchRate < match_data.MatchRate)
		{
			//choose new one and erase old one
			it = MatchMap.erase(it);
			if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
				LogMessage(0, __FUNCTION__, "\tErase old match %X-%X: %d%%\n", (*it).second.Addresses[0], (*it).second.Addresses[1], (*it).second.MatchRate);
		}
		else
		{
			//keep old one, don't add this
			add = false;
			if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
				LogMessage(0, __FUNCTION__, "\tKeep old match %X-%X: %d%%\n", (*it).second.Addresses[0], (*it).second.Addresses[1], (*it).second.MatchRate);
		}
	}

	for (multimap<va_t, va_t>::iterator it = ReverseAddressMap.find(target); it != ReverseAddressMap.end() && it->first == target; it++)
	{
		for (multimap <va_t, MatchData>::iterator it2 = MatchMap.find(it->second); it2 != MatchMap.end() && it2->first == it->second; it2++)
		{
			if ((*it2).second.MatchRate < match_data.MatchRate)
			{
				//choose new one and erase old one
				it2 = MatchMap.erase(it2);
				if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
					LogMessage(0, __FUNCTION__, "\tErase old match %X-%X: %d%%\n", (*it2).second.Addresses[0], (*it2).second.Addresses[1], (*it2).second.MatchRate);
			}
			else
			{
				//keep old one, don't add this
				add = false;
				if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(match_data.Addresses[0], match_data.Addresses[1]))
					LogMessage(0, __FUNCTION__, "\tKeep old match %X-%X: %d%%\n", (*it2).second.Addresses[0], (*it2).second.Addresses[1], (*it2).second.MatchRate);

			}
		}
	}

	if (add)
	{
		MatchMap.insert(MatchMap_Pair(src, match_data));
		ReverseAddressMap.insert(pair<va_t, va_t>(target, src));
	}
}

void MatchResults::Append(MATCHMAP* pTemporaryMap)
{
	multimap <va_t, MatchData>::iterator match_map_iter;
	for (match_map_iter = pTemporaryMap->begin();
		match_map_iter != pTemporaryMap->end();
		match_map_iter++)
	{
		AddMatchData(match_map_iter->second, __FUNCTION__);
	}
}

void MatchResults::CleanUp()
{
	multimap <va_t, MatchData>::iterator match_map_iter;
	for (match_map_iter = MatchMap.begin();
		match_map_iter != MatchMap.end();
		)
	{
		if (match_map_iter->second.Status & STATUS_MAPPING_DISABLED)
		{
			multimap <va_t, MatchData>::iterator current_map_iter = match_map_iter;
			match_map_iter++;

			if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(current_map_iter->second.Addresses[0], current_map_iter->second.Addresses[1]))
				LogMessage(0, __FUNCTION__, "%s Erase (CleanUp) %X-%X\n", __FUNCTION__, current_map_iter->second.Addresses[0], current_map_iter->second.Addresses[1]);

			for (multimap <va_t, va_t>::iterator reverse_match_map_iter = ReverseAddressMap.find(current_map_iter->second.Addresses[1]);
				reverse_match_map_iter != ReverseAddressMap.end() && reverse_match_map_iter->first == current_map_iter->second.Addresses[1];
				reverse_match_map_iter++)
			{
				reverse_match_map_iter = ReverseAddressMap.erase(reverse_match_map_iter);
			}

			MatchMap.erase(current_map_iter);

			continue;
		}
		match_map_iter++;
	}
}
