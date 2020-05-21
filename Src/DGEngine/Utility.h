#pragma once

unsigned char HexToChar(char *Hex);
unsigned char *HexToBytes(char *HexBytes, int *pLen);
unsigned char *HexToBytesWithLengthAmble(char *HexBytes);
char *BytesWithLengthAmbleToHex(unsigned char *Bytes);
int IsEqualByteWithLengthAmble(unsigned char *Bytes01, unsigned char *Bytes02);
