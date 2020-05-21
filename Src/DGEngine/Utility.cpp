#pragma warning(disable:4996)
#pragma warning(disable:4200)
#include <string>
#include <Windows.h>

unsigned char HexToChar(char *Hex)
{
    int ReturnValue = 0;
    for (int i = 0; Hex[i] && i < 2; i++)
    {
        int CurrentInt = -1;
        char c = Hex[i];
        if ('0' <= c && c <= '9')
        {
            CurrentInt = c - '0';
        }
        else if ('a' <= c && c <= 'f')
        {
            CurrentInt = c - 'a' + 10;
        }
        else if ('A' <= c && c <= 'F')
        {
            CurrentInt = c - 'A' + 10;
        }
        if (CurrentInt >= 0)
            ReturnValue = ReturnValue  *16 + CurrentInt;
    }
    return ReturnValue;
}

unsigned char *HexToBytes(char *HexBytes, int *pLen)
{
    int StrLen = strlen(HexBytes);
    *pLen = StrLen / 2;
    unsigned char *Bytes = (unsigned char*)malloc(*pLen);
    if (Bytes)
    {
        for (int i = 0; i < StrLen; i += 2)
        {
            Bytes[i / 2] = HexToChar(HexBytes + i);
        }
    }
    return Bytes;
}

unsigned char *HexToBytesWithLengthAmble(char *HexBytes)
{
    int StrLen = strlen(HexBytes);
    unsigned char *Bytes = (unsigned char*)malloc(StrLen / 2 + sizeof(short));
    *(unsigned short*)Bytes = StrLen / 2;
    if (Bytes)
    {
        for (int i = 0; i < StrLen; i += 2)
        {
            Bytes[sizeof(short) + i / 2] = HexToChar(HexBytes + i);
        }
    }
    return Bytes;
}

char *BytesWithLengthAmbleToHex(unsigned char *Bytes)
{
    int Len = *(unsigned short*)Bytes;

    char *Hex = (char*)malloc(Len  *2 + 1);
    Hex[0] = NULL;
    for (int i = 0; i < Len; i++)
    {
        char tmp_buffer[10] = { 0, };
        _snprintf(tmp_buffer, sizeof(tmp_buffer) - 1, "%.2x", Bytes[sizeof(short) + i]);
        strcat(Hex, tmp_buffer);
    }
    return Hex;
}

int IsEqualByteWithLengthAmble(unsigned char *Bytes01, unsigned char *Bytes02)
{
    if (*(unsigned short*)Bytes01 == *(unsigned short*)Bytes02)
    {
        return (memcmp(Bytes01 + sizeof(unsigned short), Bytes02 + sizeof(unsigned short), *(unsigned short*)Bytes01) == 0);
    }
    return FALSE;
}
