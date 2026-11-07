#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream>

// limitations
#define	MYSTRINGS_MAXIMUM_FILE_SIZE					300000000

// error return codes
#define MYSTRINGS_OK								0
#define MYSTRINGS_MEMORY_ALLOCATION_FAILURE			1
#define MYSTRINGS_FAILED_TO_OPEN_FILE				2
using namespace std;

class StringsExtractor
{
public:
    StringsExtractor();
    ~StringsExtractor();

    char* GenerateStrings(unsigned char* CharsOfInterest, const char* FileName, long MinimumStringSize,
                          const char* TerminatorString, long* OutputSize, string& sOutput) const;

private:
    long ReadBinaryFileIntoMemory(const CHAR* CandidateFile, CHAR** FileBuffer, DWORD* SizeOfBuffer,
                                  DWORD* SizeActuallyRead) const;
    static long ReadBinaryFileIntoMemory(WCHAR* CandidateFile, CHAR* FileBuffer, DWORD SizeOfBuffer,
                                          DWORD* SizeActuallyRead);
    static long MyGetFileSizeFromName(const CHAR* CandidateFile, DWORD* FileSize);
    static long MyGetFileSize(FILE* f);
};
