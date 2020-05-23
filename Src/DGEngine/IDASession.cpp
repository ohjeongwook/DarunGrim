#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include "IDASession.h"
#include <string>
#include "LogOperation.h"

//DB Related
#include "sqlite3.h"
#include "DiffStorage.h"

#include <unordered_set>
using namespace std;
using namespace stdext;

#include "LogOperation.h"

extern LogOperation Logger;

#define DEBUG_LEVEL 0

char *MapInfoTypesStr[] = { "Call", "Cref From", "Cref To", "Dref From", "Dref To" };
int types[] = { CREF_FROM, CREF_TO, CALL, DREF_FROM, DREF_TO, CALLED };

IDASession::IDASession(DisassemblyStorage *disassemblyStorage) :
    ClientAnalysisInfo(NULL),
    TargetFunctionAddress(0),
    m_OriginalFilePath(NULL),
    DisasmLine(NULL),
    Socket(INVALID_SOCKET),
    m_FileID(0)
{
    ClientAnalysisInfo = new AnalysisInfo;
    m_pStorage = disassemblyStorage;
}

IDASession::~IDASession()
{
    if (m_OriginalFilePath)
        free(m_OriginalFilePath);

    if (ClientAnalysisInfo)
    {
        ClientAnalysisInfo->symbol_map.clear();

        for (auto& val : ClientAnalysisInfo->map_info_map)
        {
            if (val.second)
                delete val.second;
        }

        ClientAnalysisInfo->map_info_map.clear();

        for (auto& val : ClientAnalysisInfo->address_to_instruction_hash_map)
        {
            if (val.second)
            {
                free(val.second);
            }
        }
        ClientAnalysisInfo->address_to_instruction_hash_map.clear();
        ClientAnalysisInfo->instruction_hash_map.clear();

        delete ClientAnalysisInfo;
    }
}

void IDASession::SetSocket(SOCKET socket)
{
    Socket = socket;
}

va_t *IDASession::GetMappedAddresses(va_t address, int type, int *p_length)
{
    va_t *addresses = NULL;
    int current_size = 50;

    addresses = (va_t*)malloc(sizeof(va_t)  *current_size);
    int addresses_i = 0;

    multimap <va_t, PMapInfo> *p_map_info_map;

    if (ClientAnalysisInfo && ClientAnalysisInfo->map_info_map.size() > 0)
    {
        p_map_info_map = &ClientAnalysisInfo->map_info_map;
    }
    else
    {
        p_map_info_map = new multimap <va_t, PMapInfo>();
        LoadMapInfo(p_map_info_map, address);
    }

    multimap <va_t, PMapInfo>::iterator map_info_map_pIter;

    for (map_info_map_pIter = p_map_info_map->find(address); map_info_map_pIter != p_map_info_map->end(); map_info_map_pIter++)
    {
        if (map_info_map_pIter->first != address)
            break;
        if (map_info_map_pIter->second->Type == type)
        {
            //map_info_map_pIter->second->Dst
            //TODO: add
            if (current_size < addresses_i + 2)
            {
                current_size += 50;
                addresses = (va_t*)realloc(addresses, sizeof(va_t)  *(current_size));
            }
            addresses[addresses_i] = map_info_map_pIter->second->Dst;
            addresses_i++;
            addresses[addresses_i] = NULL;
        }
    }

    if (!ClientAnalysisInfo)
    {
        p_map_info_map->clear();
        free(p_map_info_map);
    }

    if (p_length)
        *p_length = addresses_i;
    if (addresses_i == 0)
    {
        free(addresses);
        addresses = NULL;
    }
    return addresses;
}


list <va_t> *IDASession::GetFunctionAddresses()
{
    if (TargetFunctionAddress != 0)
    {
        list <va_t> *function_addresses = new list<va_t>;
        if (function_addresses)
        {
            function_addresses->push_back(TargetFunctionAddress);
        }

        return function_addresses;
    }

    int DoCrefFromCheck = FALSE;
    int DoCallCheck = TRUE;
    unordered_set <va_t> function_address_hash;
    unordered_map <va_t, short> addresses;

    if (DoCrefFromCheck)
    {
        Logger.Log(10, LOG_IDA_CONTROLLER, "addresses.size() = %u\n", addresses.size());

        for (auto& val: ClientAnalysisInfo->map_info_map)
        {
            Logger.Log(10, LOG_IDA_CONTROLLER, "%X-%X(%s) ", val.first, val.second->Dst, MapInfoTypesStr[val.second->Type]);
            if (val.second->Type == CREF_FROM)
            {
                unordered_map <va_t, short>::iterator iter = addresses.find(val.second->Dst);
                if (iter != addresses.end())
                {
                    iter->second = FALSE;
                }
            }
        }
        Logger.Log(10, LOG_IDA_CONTROLLER, "%s\n", __FUNCTION__);

        for (auto& val : ClientAnalysisInfo->address_to_instruction_hash_map)
        {
            addresses.insert(pair<va_t, short>(val.first, DoCrefFromCheck ? TRUE : FALSE));
        }

        Logger.Log(10, LOG_IDA_CONTROLLER, "addresses.size() = %u\n", addresses.size());
        for (auto& val : addresses)
        {
            if (val.second)
            {
                Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Function %X\n", __FUNCTION__, m_FileID, val.first);
                function_address_hash.insert(val.first);
            }
        }
    }
    else
    {
        m_pStorage->ReadFunctionAddressMap(m_FileID, function_address_hash);
    }

    if (DoCallCheck && ClientAnalysisInfo)
    {
        for (auto& val : ClientAnalysisInfo->map_info_map)
        {
            if (val.second->Type == CALL)
            {
                if (function_address_hash.find(val.second->Dst) == function_address_hash.end())
                {
                    Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Function %X (by Call Recognition)\n", __FUNCTION__, m_FileID, val.second->Dst);
                    function_address_hash.insert(val.second->Dst);
                }
            }
        }
    }

    list <va_t> *function_addresses = new list<va_t>;
    if (function_addresses)
    {
        for (auto& val : function_address_hash)
        {
            function_addresses->push_back(val);
            Logger.Log(11, LOG_IDA_CONTROLLER, "%s: ID = %d Function %X\n", __FUNCTION__, m_FileID, val);
        }

        Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Returns(%u entries)\n", __FUNCTION__, m_FileID, function_addresses->size());
    }
    return function_addresses;
}

#undef USE_LEGACY_MAP_FOR_ADDRESS_MAP
void IDASession::RemoveFromInstructionHashHash(va_t address)
{
    unsigned char *InstructionHash = NULL;

    char *InstructionHashStr = m_pStorage->ReadInstructionHash(m_FileID, address);

    if (InstructionHashStr)
    {
        InstructionHash = HexToBytesWithLengthAmble(InstructionHashStr);
    }

    if (InstructionHash)
    {
        multimap <unsigned char*, va_t, hash_compare_instruction_hash>::iterator instruction_hash_map_PIter;
        for (instruction_hash_map_PIter = ClientAnalysisInfo->instruction_hash_map.find(InstructionHash);
            instruction_hash_map_PIter != ClientAnalysisInfo->instruction_hash_map.end();
            instruction_hash_map_PIter++
            )
        {
            if (!IsEqualByteWithLengthAmble(instruction_hash_map_PIter->first, InstructionHash))
                break;
            if (instruction_hash_map_PIter->second == address)
            {
                ClientAnalysisInfo->instruction_hash_map.erase(instruction_hash_map_PIter);
                break;
            }
        }
        free(InstructionHash);
    }
}

char *IDASession::GetInstructionHashStr(va_t address)
{
    if (ClientAnalysisInfo && ClientAnalysisInfo->address_to_instruction_hash_map.size() > 0)
    {
        multimap <va_t, unsigned char*>::iterator address_to_instruction_hash_map_PIter = ClientAnalysisInfo->address_to_instruction_hash_map.find(address);
        if (address_to_instruction_hash_map_PIter != ClientAnalysisInfo->address_to_instruction_hash_map.end())
        {
            return BytesWithLengthAmbleToHex(address_to_instruction_hash_map_PIter->second);
        }
    }
    else
    {
        char *InstructionHashPtr = m_pStorage->ReadInstructionHash(m_FileID, address);
        return InstructionHashPtr;
    }
    return NULL;
}

char *IDASession::GetName(va_t address)
{
    char *Name = m_pStorage->ReadName(m_FileID, address);
    return Name;
}

va_t IDASession::GetBlockAddress(va_t address)
{
    return m_pStorage->ReadBlockStartAddress(m_FileID, address);
}

void IDASession::DumpBlockInfo(va_t block_address)
{
    int addresses_number;
    char *type_descriptions[] = { "Cref From", "Cref To", "Call", "Dref From", "Dref To" };
    for (int i = 0; i < sizeof(types) / sizeof(int); i++)
    {
        va_t *addresses = GetMappedAddresses(block_address, types[i], &addresses_number);
        if (addresses)
        {
            Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d %s: ", __FUNCTION__, m_FileID, type_descriptions[i]);
            for (int j = 0; j < addresses_number; j++)
            {
                Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d %X ", __FUNCTION__, m_FileID, addresses[j]);
            }
            Logger.Log(10, LOG_IDA_CONTROLLER, "\n");
        }
    }
    char *hex_str = GetInstructionHashStr(block_address);
    if (hex_str)
    {
        Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d instruction_hash: %s\n", __FUNCTION__, m_FileID, hex_str);
        free(hex_str);
    }
}

const char *GetAnalysisDataTypeStr(int type)
{
    static const char *Types[] = { "BASIC_BLOCK", "MAP_INFO", "FILE_INFO", "END_OF_DATA" };
    if (type < sizeof(Types) / sizeof(Types[0]))
        return Types[type];
    return "Unknown";
}

enum { TYPE_FILE_INFO, TYPE_ADDRESS_MAP, TYPE_ADDRESS_DISASSEMBLY_MAP, TYPE_INSTRUCTION_HASH_MAP, TYPE_TWO_LEVEL_INSTRUCTION_HASH_MAP, TYPE_address_to_instruction_hash_map, TYPE_NAME_MAP, TYPE_ADDRESS_NAME_MAP, TYPE_MAP_INFO_MAP };

const char *GetFileDataTypeStr(int type)
{
    static const char *Types[] = { "FILE_INFO", "ADDRESS_MAP", "ADDRESS_DISASSEMBLY_MAP", "INSTRUCTION_HASH_MAP", "TWO_LEVEL_INSTRUCTION_HASH_MAP", "address_to_instruction_hash_map", "NAME_MAP", "ADDRESS_NAME_MAP", "MAP_INFO_MAP" };
    if (type < sizeof(Types) / sizeof(Types[0]))
        return Types[type];
    return "Unknown";
}

BOOL IDASession::Save(char *DataFile, DWORD Offset, DWORD dwMoveMethod, unordered_set <va_t> *pSelectedAddresses)
{
    return TRUE;
}

BOOL IDASession::Retrieve(char *DataFile, DWORD Offset, DWORD Length)
{
    return TRUE;
}

char *IDASession::GetOriginalFilePath()
{
    return m_OriginalFilePath;
}

BOOL IDASession::LoadBasicBlock()
{
    if (ClientAnalysisInfo->instruction_hash_map.size() == 0)
    {
        char conditionStr[50] = { 0, };
        if (TargetFunctionAddress)
        {
            _snprintf(conditionStr, sizeof(conditionStr) - 1, "AND FunctionAddress = '%d'", TargetFunctionAddress);
        }

        m_pStorage->ReadBasicBlockInfo(m_FileID, conditionStr, ClientAnalysisInfo);
    }
    return TRUE;
}

/*
FunctionAddress = 0 : Retrieve All Functions
    else			: Retrieve That Specific Function
*/

void IDASession::SetFileID(int FileID)
{
    m_FileID = FileID;
}

void IDASession::LoadMapInfo(multimap <va_t, PMapInfo> *p_map_info_map, va_t Address, bool IsFunction)
{
    if (Address == 0)
    {
        p_map_info_map = m_pStorage->ReadMapInfo(m_FileID);
    }
    else
    {
        p_map_info_map = m_pStorage->ReadMapInfo(m_FileID, Address, IsFunction);
    }

    BuildCrefToMap(p_map_info_map);
}


void IDASession::BuildCrefToMap(multimap <va_t, PMapInfo> *p_map_info_map)
{
    for (auto& val : *p_map_info_map)
    {
        if (val.second->Type == CREF_FROM)
        {
            CrefToMap.insert(pair<va_t, va_t>(val.second->Dst, val.first));
        }
    }
}

BOOL IDASession::Load()
{
    m_OriginalFilePath = m_pStorage->GetOriginalFilePath(m_FileID);

    LoadBasicBlock();
    LoadMapInfo(&(ClientAnalysisInfo->map_info_map), TargetFunctionAddress, true);

    return TRUE;
}

void IDASession::DeleteMatchInfo(DiffStorage *p_diffStorage, int FileID, va_t FunctionAddress)
{
    p_diffStorage->DeleteMatchInfo(FileID, FunctionAddress);
}

void IDASession::AddAnalysisTargetFunction(va_t FunctionAddress)
{
    Logger.Log(10, LOG_IDA_CONTROLLER, "Add Analysis Target Function: %X\n", FunctionAddress);
    TargetFunctionAddress = FunctionAddress;
}

typedef struct {
    va_t address;
    va_t child_address;
} AddressPair;

void IDASession::GenerateTwoLevelInstructionHash()
{
    /*
    multimap <unsigned char *, va_t, hash_compare_instruction_hash>::iterator instruction_hash_map_pIter;
    for (instruction_hash_map_pIter = ClientAnalysisInfo->instruction_hash_map.begin();
        instruction_hash_map_pIter != ClientAnalysisInfo->instruction_hash_map.end();
        instruction_hash_map_pIter++)

    {
        if(ClientAnalysisInfo->instruction_hash_map.count(instruction_hash_map_pIter->first)>1)
        {
            int addresses_number = 0;
            va_t *addresses = GetMappedAddresses(instruction_hash_map_pIter->second, CREF_FROM, &addresses_number);
            if(!addresses)
                addresses = GetMappedAddresses(instruction_hash_map_pIter->second, CREF_TO, NULL);
            if(addresses)
            {
                int TwoLevelInstructionHashLength = 0;
                TwoLevelInstructionHashLength += *(unsigned short *)instruction_hash_map_pIter->first; //+
                multimap <va_t,  unsigned char *>::iterator address_to_instruction_hash_map_Iter;
                for (int i = 0;i<addresses_number;i++)
                {
                    address_to_instruction_hash_map_Iter = ClientAnalysisInfo->address_to_instruction_hash_map.find(addresses[i]);
                    if(address_to_instruction_hash_map_Iter != ClientAnalysisInfo->address_to_instruction_hash_map.end())
                    {
                        TwoLevelInstructionHashLength += *(unsigned short *)address_to_instruction_hash_map_Iter->second; //+
                    }
                }

                if(TwoLevelInstructionHashLength>0)
                {
                    unsigned char *TwoLevelInstructionHash = (unsigned char *)malloc(TwoLevelInstructionHashLength+sizeof(short));
                    if(TwoLevelInstructionHash)
                    {
                        *(unsigned short *)TwoLevelInstructionHash = TwoLevelInstructionHashLength;

                        int Offset = sizeof(short);
                        memcpy(TwoLevelInstructionHash+Offset, instruction_hash_map_pIter->first+sizeof(short), *(unsigned short *)instruction_hash_map_pIter->first);
                        Offset += *(unsigned short *)instruction_hash_map_pIter->first;
                        for (int i = 0;i<addresses_number;i++)
                        {
                            address_to_instruction_hash_map_Iter = ClientAnalysisInfo->address_to_instruction_hash_map.find(addresses[i]);
                            if(address_to_instruction_hash_map_Iter != ClientAnalysisInfo->address_to_instruction_hash_map.end())
                            {
                                memcpy(TwoLevelInstructionHash+Offset, address_to_instruction_hash_map_Iter->second+sizeof(short), *(unsigned short *)address_to_instruction_hash_map_Iter->second);
                                Offset += *(unsigned short *)address_to_instruction_hash_map_Iter->second;
                            }
                        }
                        ClientAnalysisInfo->instruction_hash_map.insert(InstructionHashAddress_Pair(TwoLevelInstructionHash, instruction_hash_map_pIter->second));
                    }
                }
            }
        }
    }*/
}

void IDASession::DumpAnalysisInfo()
{
    if (ClientAnalysisInfo)
    {
        Logger.Log(10, LOG_IDA_CONTROLLER, "OriginalFilePath = %s\n", ClientAnalysisInfo->file_info.OriginalFilePath);
        Logger.Log(10, LOG_IDA_CONTROLLER, "ComputerName = %s\n", ClientAnalysisInfo->file_info.ComputerName);
        Logger.Log(10, LOG_IDA_CONTROLLER, "UserName = %s\n", ClientAnalysisInfo->file_info.UserName);
        Logger.Log(10, LOG_IDA_CONTROLLER, "CompanyName = %s\n", ClientAnalysisInfo->file_info.CompanyName);
        Logger.Log(10, LOG_IDA_CONTROLLER, "FileVersion = %s\n", ClientAnalysisInfo->file_info.FileVersion);
        Logger.Log(10, LOG_IDA_CONTROLLER, "FileDescription = %s\n", ClientAnalysisInfo->file_info.FileDescription);
        Logger.Log(10, LOG_IDA_CONTROLLER, "InternalName = %s\n", ClientAnalysisInfo->file_info.InternalName);
        Logger.Log(10, LOG_IDA_CONTROLLER, "ProductName = %s\n", ClientAnalysisInfo->file_info.ProductName);
        Logger.Log(10, LOG_IDA_CONTROLLER, "ModifiedTime = %s\n", ClientAnalysisInfo->file_info.ModifiedTime);
        Logger.Log(10, LOG_IDA_CONTROLLER, "MD5Sum = %s\n", ClientAnalysisInfo->file_info.MD5Sum);

        Logger.Log(10, LOG_IDA_CONTROLLER, "instruction_hash_map = %u\n", ClientAnalysisInfo->instruction_hash_map.size());
    }
}

BOOL IDASession::SendTLVData(char type, PBYTE data, DWORD data_length)
{
    if (Socket != INVALID_SOCKET)
    {
        BOOL ret = ::SendTLVData(Socket,
            type,
            data,
            data_length);
        if (!ret)
            Socket = INVALID_SOCKET;
        return ret;
    }
    return FALSE;
}

char *IDASession::GetDisasmLines(unsigned long StartAddress, unsigned long EndAddress)
{
    char *DisasmLines = m_pStorage->ReadDisasmLine(m_FileID, StartAddress);

    if (DisasmLines)
    {
        Logger.Log(10, LOG_IDA_CONTROLLER, "DisasmLines = %s\n", DisasmLines);
        return DisasmLines;
    }
    return _strdup("");
}

string IDASession::GetInputName()
{
    string input_name;

    if (SendTLVData(GET_INPUT_NAME, (PBYTE)"", 1))
    {
        char type;
        DWORD length;

        PBYTE data = RecvTLVData(Socket, &type, &length);
        input_name = (char*)data;
    }
    return input_name;
}

void IDASession::RetrieveIdentity()
{
    Identity = GetInputName();
}

string IDASession::GetIdentity()
{
    return Identity;
}

PBasicBlock IDASession::GetBasicBlock(va_t address)
{
    return m_pStorage->ReadBasicBlock(m_FileID, address);
}

void IDASession::FreeDisasmLines()
{
    if (DisasmLine)
        free(DisasmLine);
}

void IDASession::JumpToAddress(unsigned long address)
{
    SendTLVData(JUMP_TO_ADDR, (PBYTE)&address, sizeof(va_t));
}

void IDASession::ColorAddress(unsigned long start_address, unsigned long end_address, unsigned long color)
{
    unsigned long data[3];
    data[0] = start_address;
    data[1] = end_address;
    data[2] = color;
    SendTLVData(COLOR_ADDRESS, (PBYTE)data, sizeof(data));
}

list <BLOCK> IDASession::GetFunctionMemberBlocks(unsigned long function_address)
{
    list <BLOCK> block_list;

    if (ClientAnalysisInfo)
    {
        list <va_t> address_list;
        unordered_set <va_t> checked_addresses;
        address_list.push_back(function_address);

        BLOCK block;
        block.Start = function_address;
        PBasicBlock pBasicBlock = GetBasicBlock(function_address);
        block.End = pBasicBlock->EndAddress;
        block_list.push_back(block);

        checked_addresses.insert(function_address);

        for (va_t currentAddress: address_list)
        {
            int addresses_number;
            va_t *p_addresses = GetMappedAddresses(currentAddress, CREF_FROM, &addresses_number);
            if (p_addresses && addresses_number > 0)
            {
                for (int i = 0; i < addresses_number; i++)
                {
                    va_t address = p_addresses[i];
                    if (address)
                    {
                        if (FunctionHeads.find(address) != FunctionHeads.end())
                            continue;

                        if (checked_addresses.find(address) == checked_addresses.end())
                        {
                            address_list.push_back(address);
                            block.Start = address;
                            PBasicBlock pBasicBlock = GetBasicBlock(address);
                            block.End = pBasicBlock->EndAddress;
                            block_list.push_back(block);

                            checked_addresses.insert(address);
                        }
                    }
                }
                free(p_addresses);
            }
        }
    }
    else
    {
        block_list = m_pStorage->ReadFunctionMemberAddresses(m_FileID, function_address);
    }

    return block_list;
}

void IDASession::MergeBlocks()
{
    multimap <va_t, PMapInfo>::iterator last_iter = ClientAnalysisInfo->map_info_map.end();
    multimap <va_t, PMapInfo>::iterator iter;
    multimap <va_t, PMapInfo>::iterator child_iter;

    int NumberOfChildren = 1;
    for (iter = ClientAnalysisInfo->map_info_map.begin();
        iter != ClientAnalysisInfo->map_info_map.end();
        iter++
        )
    {
        if (iter->second->Type == CREF_FROM)
        {
            BOOL bHasOnlyOneChild = FALSE;
            if (last_iter != ClientAnalysisInfo->map_info_map.end())
            {
                if (last_iter->first == iter->first)
                {
                    NumberOfChildren++;
                }
                else
                {
                    Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Number Of Children for %X  = %u\n",
                        __FUNCTION__, m_FileID,
                        last_iter->first,
                        NumberOfChildren);
                    if (NumberOfChildren == 1)
                        bHasOnlyOneChild = TRUE;
                    multimap <va_t, PMapInfo>::iterator next_iter = iter;
                    next_iter++;
                    if (next_iter == ClientAnalysisInfo->map_info_map.end())
                    {
                        last_iter = iter;
                        bHasOnlyOneChild = TRUE;
                    }
                    NumberOfChildren = 1;
                }
            }
            if (bHasOnlyOneChild)
            {
                int NumberOfParents = 0;
                for (child_iter = ClientAnalysisInfo->map_info_map.find(last_iter->second->Dst);
                    child_iter != ClientAnalysisInfo->map_info_map.end() && child_iter->first == last_iter->second->Dst;
                    child_iter++)
                {
                    if (child_iter->second->Type == CREF_TO && child_iter->second->Dst != last_iter->first)
                    {
                        Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Found %X -> %X\n",
                            __FUNCTION__, m_FileID,
                            child_iter->second->Dst, child_iter->first);
                        NumberOfParents++;
                    }
                }
                if (NumberOfParents == 0)
                {
                    Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Found Mergable Nodes %X -> %X\n",
                        __FUNCTION__, m_FileID,
                        last_iter->first, last_iter->second->Dst);
                }
            }
            last_iter = iter;
        }
    }
}

int IDASession::GetFileID()
{
    return m_FileID;
}

multimap <va_t, va_t> *IDASession::GetFunctionToBlock()
{
    Logger.Log(10, LOG_IDA_CONTROLLER, "LoadFunctionMembersMap\n");
    return &FunctionToBlock;
}

static int ReadAddressToFunctionMapResultsCallback(void *arg, int argc, char **argv, char **names)
{
    unordered_map <va_t, va_t> *AddressToFunctionMap = (unordered_map <va_t, va_t>*)arg;
    if (AddressToFunctionMap)
    {
#if DEBUG_LEVEL > 1
        Logger.Log(10, "%s: ID = %d strtoul10(%s) = 0x%X, strtoul10(%s) = 0x%X\n", __FUNCTION__, m_FileID, argv[0], strtoul10(argv[0]), argv[1], strtoul10(argv[1]));
#endif
        AddressToFunctionMap->insert(pair <va_t, va_t>(strtoul10(argv[0]), strtoul10(argv[1])));
    }
    return 0;
}

void IDASession::LoadBlockToFunction()
{
    int Count = 0;

    Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d GetFunctionAddresses\n", __FUNCTION__);
    list <va_t> *function_addresses = GetFunctionAddresses();
    if (function_addresses)
    {
        Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d Function %u entries\n", __FUNCTION__, m_FileID, function_addresses->size());

        unordered_map<va_t, va_t> addresses;
        unordered_map<va_t, va_t> membership_hash;

        for (va_t address : *function_addresses)
        {
            list <BLOCK> function_member_blocks = GetFunctionMemberBlocks(address);

            for (auto& val : function_member_blocks)
            {
                va_t addr = val.Start;
                BlockToFunction.insert(pair <va_t, va_t>(addr, address));

                if (addresses.find(addr) == addresses.end())
                {
                    addresses.insert(pair<va_t, va_t>(addr, 1));
                }
                else
                {
                    addresses[addr] += 1;
                }

                if (membership_hash.find(addr) == membership_hash.end())
                {
                    membership_hash.insert(pair<va_t, va_t>(addr, address));
                }
                else
                {
                    membership_hash[addr] += address;
                }
            }
        }

        for (auto& val : addresses)
        {
            if (val.second > 1)
            {
                bool function_start = true;
                for (multimap<va_t, va_t>::iterator it2 = CrefToMap.find(val.first);
                    it2 != CrefToMap.end() && it2->first == val.first;
                    it2++
                    )
                {
                    unordered_map<va_t, va_t>::iterator current_membership_it = membership_hash.find(val.first);
                    va_t parent = it2->second;
                    Logger.Log(10, LOG_IDA_CONTROLLER, "Found parent for %X -> %X\n", val.first, parent);
                    unordered_map<va_t, va_t>::iterator parent_membership_it = membership_hash.find(parent);
                    if (current_membership_it != membership_hash.end() && parent_membership_it != membership_hash.end())
                    {
                        if (current_membership_it->second == parent_membership_it->second)
                        {
                            function_start = false;
                            break;
                        }
                    }
                }

                Logger.Log(10, LOG_IDA_CONTROLLER, "Multiple function membership: %X (%d) %s\n", val.first, val.second, function_start ? "Possible Head" : "Member");

                if (function_start)
                {
                    va_t function_start_addr = val.first;
                    FunctionHeads.insert(function_start_addr);
                    list <BLOCK> function_member_blocks = GetFunctionMemberBlocks(function_start_addr);
                    unordered_map<va_t, va_t>::iterator function_start_membership_it = membership_hash.find(function_start_addr);

                    for (list <BLOCK>::iterator it2 = function_member_blocks.begin();
                        it2 != function_member_blocks.end();
                        it2++
                        )
                    {
                        va_t addr = (*it2).Start;

                        unordered_map<va_t, va_t>::iterator current_membership_it = membership_hash.find(addr);

                        if (function_start_membership_it->second != current_membership_it->second)
                            continue;

                        for (multimap <va_t, va_t>::iterator a2f_it = BlockToFunction.find(addr);
                            a2f_it != BlockToFunction.end() && a2f_it->first == addr;
                            a2f_it++
                            )
                        {
                            Logger.Log(10, LOG_IDA_CONTROLLER, "\tRemoving Block: %X Function: %X\n", a2f_it->first, a2f_it->second);
                            a2f_it = BlockToFunction.erase(a2f_it);
                        }
                        BlockToFunction.insert(pair <va_t, va_t>(addr, function_start_addr));
                        Logger.Log(10, LOG_IDA_CONTROLLER, "\tAdding Block: %X Function: %X\n", addr, function_start_addr);
                    }
                }
            }
        }
        function_addresses->clear();
        delete function_addresses;

        for (auto& val : BlockToFunction)
        {
            FunctionToBlock.insert(pair<va_t, va_t>(val.second, val.first));
        }

        Logger.Log(10, LOG_IDA_CONTROLLER, "%s: ID = %d BlockToFunction %u entries\n", __FUNCTION__, m_FileID, BlockToFunction.size());
    }
}

BOOL IDASession::FixFunctionAddresses()
{
    BOOL is_fixed = FALSE;
    Logger.Log(10, LOG_IDA_CONTROLLER, "%s", __FUNCTION__);
    LoadBlockToFunction();

    if (m_pStorage)
        m_pStorage->BeginTransaction();

    for (auto& val : BlockToFunction)
    {
        //StartAddress: val.first
        //FunctionAddress: val.second
        Logger.Log(10, LOG_IDA_CONTROLLER, "Updating BasicBlockTable Address = %X Function = %X\n", val.second, val.first);

        m_pStorage->UpdateBasicBlock(m_FileID, val.first, val.second);
        is_fixed = TRUE;
    }

    if (m_pStorage)
        m_pStorage->EndTransaction();

    ClearBlockToFunction();

    return is_fixed;
}

bool IDASession::SendMatchedAddrTLVData(FunctionMatchInfo& Data)
{
    return SendTLVData(
        MATCHED_ADDR,
        (PBYTE) & (Data),
        sizeof(Data));
}

bool IDASession::SendAddrTypeTLVData(int Type, va_t Start, va_t End)
{
    va_t StartToEnd[2];

    StartToEnd[0] = Start;
    StartToEnd[1] = End;

    return SendTLVData(
        Type,
        (PBYTE)StartToEnd,
        sizeof(StartToEnd));
}

