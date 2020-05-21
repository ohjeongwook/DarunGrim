#include "MatchResults.h"
#include "Log.h"

MatchResults::MatchResults() :pDumpAddressChecker(NULL)
{
}

void MatchResults::SetDumpAddressChecker(DumpAddressChecker *p_dump_address_checker)
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
        for (va_t address : sources)
        {
            EraseSource(targets, address, source, target);
        }
        sources.clear();

        for (va_t address : targets)
        {
            EraseTarget(sources, address, source, target);
        }
        targets.clear();
    }
}

multimap <va_t, MatchData>::iterator MatchResults::Erase(multimap <va_t, MatchData>::iterator matchMapIterator)
{
    if (matchMapIterator != MatchMap.end())
    {
        if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(matchMapIterator->second.Addresses[0], matchMapIterator->second.Addresses[1]))
            LogMessage(0, __FUNCTION__, "%s %X-%X\n", __FUNCTION__, matchMapIterator->second.Addresses[0], matchMapIterator->second.Addresses[1]);

        for (
            multimap <va_t, va_t>::iterator it = ReverseAddressMap.find(matchMapIterator->second.Addresses[1]);
            it != ReverseAddressMap.end() && it->first == matchMapIterator->second.Addresses[1];
            it++)
        {
            if (it->second == matchMapIterator->first)
                it = ReverseAddressMap.erase(it);
        }
        matchMapIterator = MatchMap.erase(matchMapIterator);
    }
    return matchMapIterator;
}

void MatchResults::AddMatchData(MatchData& match_data, const char *debug_str)
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

void MatchResults::Append(MATCHMAP *pTemporaryMap)
{
    multimap <va_t, MatchData>::iterator matchMapIterator;
    for (matchMapIterator = pTemporaryMap->begin(); matchMapIterator != pTemporaryMap->end(); matchMapIterator++)
    {
        AddMatchData(matchMapIterator->second, __FUNCTION__);
    }
}

void MatchResults::CleanUp()
{
    for (multimap <va_t, MatchData>::iterator it = MatchMap.begin(); it != MatchMap.end();)
    {
        if (it->second.Status & STATUS_MAPPING_DISABLED)
        {
            multimap <va_t, MatchData>::iterator current_map_iter = it;
            it++;

            if (pDumpAddressChecker && pDumpAddressChecker->IsDumpPair(current_map_iter->second.Addresses[0], current_map_iter->second.Addresses[1]))
                LogMessage(0, __FUNCTION__, "%s Erase (CleanUp) %X-%X\n", __FUNCTION__, current_map_iter->second.Addresses[0], current_map_iter->second.Addresses[1]);

            for (multimap <va_t, va_t>::iterator reverse_matchMapIterator = ReverseAddressMap.find(current_map_iter->second.Addresses[1]);
                reverse_matchMapIterator != ReverseAddressMap.end() && reverse_matchMapIterator->first == current_map_iter->second.Addresses[1];
                reverse_matchMapIterator++)
            {
                reverse_matchMapIterator = ReverseAddressMap.erase(reverse_matchMapIterator);
            }

            MatchMap.erase(current_map_iter);

            continue;
        }
        it++;
    }
}

MatchMapList* MatchResults::GetMatchData(int index, va_t address, BOOL erase)
{
    MatchMapList* pMatchMapList = NULL;

    pMatchMapList = new MatchMapList();
    multimap<va_t, va_t> addressPairs;

    if (index == 1)
    {
        for (multimap <va_t, va_t>::iterator it = ReverseAddressMap.find(address);
            it != ReverseAddressMap.end() && it->first == address;
            it++)
        {
            addressPairs.insert(pair<va_t, va_t>(it->second, address));

            if (erase)
            {
                it = ReverseAddressMap.erase(it);
            }
        }
    }
    else
    {
        addressPairs.insert(pair<va_t, va_t>(address, 0));
    }

    for (auto& val : addressPairs)
    {
        va_t sourceAddress = val.first;
        va_t targetAddress = val.second;

        multimap <va_t, MatchData>::iterator matchMapIterator;
        for (matchMapIterator = MatchMap.find(sourceAddress);
            matchMapIterator != MatchMap.end() && matchMapIterator->first == sourceAddress;
            matchMapIterator++
            )
        {
            if (targetAddress != 0 && matchMapIterator->second.Addresses[1] != targetAddress)
                continue;

            // LogMessage(20, LOG_DIFF_MACHINE, "%s: %u 0x%X returns %X-%X\r\n", __FUNCTION__, index, sourceAddress, matchMapIterator->second.Addresses[0], matchMapIterator->second.Addresses[1]);

            if (erase)
            {
                //Erase matching reverse address map entries
                matchMapIterator = MatchMap.erase(matchMapIterator);

                va_t match_targetAddress = matchMapIterator->second.Addresses[1];
                va_t match_sourceAddress = matchMapIterator->second.Addresses[0];

                for (multimap <va_t, va_t>::iterator reverse_matchMapIterator = ReverseAddressMap.find(match_targetAddress);
                    reverse_matchMapIterator != ReverseAddressMap.end() && reverse_matchMapIterator->first == match_targetAddress;
                    reverse_matchMapIterator++
                    )
                {
                    if (reverse_matchMapIterator->second == match_sourceAddress)
                        reverse_matchMapIterator = ReverseAddressMap.erase(reverse_matchMapIterator);
                }
            }
            else
            {
                MatchData* new_match_data = new MatchData();
                memcpy(new_match_data, &matchMapIterator->second, sizeof(MatchData));
                pMatchMapList->Add(new_match_data);
            }
        }
    }

    return pMatchMapList;
}
