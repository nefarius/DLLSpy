#pragma once
#include <windows.h>
#include <stdio.h>
#include <iostream>

// limitations
#define	MYSTRINGS_MAXIMUM_FILE_SIZE					30000000

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

    char* StringsExtractor::GenerateStrings(unsigned char* CharsOfInterest, char* FileName, long MinimumStringSize,
                                            char* TerminatorString, long* OutputSize, string& sOutput) const;

private:
    long StringsExtractor::ReadBinaryFileIntoMemory(CHAR* CandidateFile, CHAR** FileBuffer, DWORD* SizeOfBuffer,
                                                    DWORD* SizeActuallyRead) const;
    static long StringsExtractor::ReadBinaryFileIntoMemory(WCHAR* CandidateFile, CHAR* FileBuffer, DWORD SizeOfBuffer,
                                                           DWORD* SizeActuallyRead);
    static long StringsExtractor::MyGetFileSizeFromName(CHAR* CandidateFile, DWORD* FileSize);
    static long StringsExtractor::MyGetFileSize(FILE* f);
};
