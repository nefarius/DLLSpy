#include <windows.h>

#include "PeImports.h"

namespace
{
    // Older delay-load descriptors store virtual addresses when Attributes bit 0 is clear.
    struct DelayLoadDescriptor
    {
        DWORD Attributes;
        DWORD DllNameRVA;
        DWORD ModuleHandleRVA;
        DWORD ImportAddressTableRVA;
        DWORD ImportNameTableRVA;
        DWORD BoundImportAddressTableRVA;
        DWORD UnloadInformationTableRVA;
        DWORD TimeDateStamp;
    };

    class MappedFile
    {
    public:
        MappedFile() = default;
        ~MappedFile()
        {
            if (base != nullptr)
                UnmapViewOfFile(base);
            if (hMapping != nullptr)
                CloseHandle(hMapping);
            if (hFile != INVALID_HANDLE_VALUE)
                CloseHandle(hFile);
        }

        MappedFile(const MappedFile&) = delete;
        MappedFile& operator=(const MappedFile&) = delete;
        MappedFile(MappedFile&&) = delete;
        MappedFile& operator=(MappedFile&&) = delete;

        bool Open(const string& sPath)
        {
            hFile = CreateFileA(sPath.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (hFile == INVALID_HANDLE_VALUE)
                return false;

            LARGE_INTEGER fileSize{};
            if (!GetFileSizeEx(hFile, &fileSize) || fileSize.HighPart != 0 ||
                fileSize.LowPart < sizeof(IMAGE_DOS_HEADER))
                return false;

            size = fileSize.LowPart;
            hMapping = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
            if (hMapping == nullptr)
                return false;

            base = static_cast<const BYTE*>(MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0));
            return base != nullptr;
        }

        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapping = nullptr;
        const BYTE* base = nullptr;
        DWORD size = 0;
    };

    const BYTE* RvaToPtr(const BYTE* base, DWORD fileSize, const IMAGE_SECTION_HEADER* sections, WORD sectionCount,
                          DWORD rva, DWORD needed)
    {
        if (rva == 0 || needed == 0 || needed > fileSize)
            return nullptr;

        for (WORD i = 0; i < sectionCount; ++i)
        {
            const DWORD virtualAddress = sections[i].VirtualAddress;
            if (rva < virtualAddress)
                continue;

            const DWORD virtualSize = sections[i].Misc.VirtualSize;
            const DWORD rawSize = sections[i].SizeOfRawData;
            const DWORD span = virtualSize > rawSize ? virtualSize : rawSize;
            const DWORD delta = rva - virtualAddress;
            if (span == 0 || delta >= span || rawSize == 0 || delta >= rawSize)
                continue;

            const DWORD raw = sections[i].PointerToRawData;
            if (raw > fileSize || delta > fileSize - raw)
                continue;

            const DWORD offset = raw + delta;
            if (needed > fileSize - offset)
                return nullptr;

            return base + offset;
        }

        return nullptr;
    }

    string ReadCString(const BYTE* base, DWORD fileSize, const BYTE* start)
    {
        if (start == nullptr || start < base || start >= base + fileSize)
            return {};

        const DWORD available = fileSize - static_cast<DWORD>(start - base);
        DWORD length = 0;
        constexpr DWORD kMaxName = 260;
        while (length < available && length < kMaxName && start[length] != 0)
            ++length;

        if (length == 0 || length == available)
            return {};

        return string(reinterpret_cast<const char*>(start), length);
    }

    void AddDllName(const BYTE* base, DWORD fileSize, const IMAGE_SECTION_HEADER* sections, WORD sectionCount,
                    DWORD nameRva, DllRefSource eSource, vector<ImportRef>& vImports)
    {
        const BYTE* namePtr = RvaToPtr(base, fileSize, sections, sectionCount, nameRva, 2);
        const string sName = ReadCString(base, fileSize, namePtr);
        if (!sName.empty())
            vImports.push_back(ImportRef{sName, eSource});
    }

    DWORD DelayNameRva(const DelayLoadDescriptor* descriptor, ULONGLONG imageBase)
    {
        const DWORD name = descriptor->DllNameRVA;
        if ((descriptor->Attributes & 0x1u) != 0)
            return name;

        if (imageBase == 0 || static_cast<ULONGLONG>(name) < imageBase)
            return 0;

        const ULONGLONG rva = static_cast<ULONGLONG>(name) - imageBase;
        if (rva > MAXDWORD)
            return 0;

        return static_cast<DWORD>(rva);
    }

    struct ImageDirectories
    {
        DWORD importRva = 0;
        DWORD importSize = 0;
        DWORD delayRva = 0;
        DWORD delaySize = 0;
        ULONGLONG imageBase = 0;
    };

    bool ReadDirectories(const BYTE* optional, WORD magic, DWORD optionalSize, ImageDirectories& directories)
    {
        if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
        {
            if (optionalSize < sizeof(IMAGE_OPTIONAL_HEADER64))
                return false;

            const auto header = reinterpret_cast<const IMAGE_OPTIONAL_HEADER64*>(optional);
            directories.imageBase = header->ImageBase;
            if (header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            {
                directories.importRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                directories.importSize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
            if (header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
            {
                directories.delayRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
                directories.delaySize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
            }
            return true;
        }

        if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
        {
            if (optionalSize < sizeof(IMAGE_OPTIONAL_HEADER32))
                return false;

            const auto header = reinterpret_cast<const IMAGE_OPTIONAL_HEADER32*>(optional);
            directories.imageBase = header->ImageBase;
            if (header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_IMPORT)
            {
                directories.importRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
                directories.importSize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
            }
            if (header->NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
            {
                directories.delayRva = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
                directories.delaySize = header->DataDirectory[IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
            }
            return true;
        }

        return false;
    }

    bool ParseImports(const BYTE* base, DWORD fileSize, vector<ImportRef>& vImports)
    {
        if (fileSize < sizeof(IMAGE_DOS_HEADER))
            return false;

        const auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
        if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0)
            return false;

        const auto ntOffset = static_cast<DWORD>(dos->e_lfanew);
        if (ntOffset > fileSize || fileSize - ntOffset < sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER))
            return false;

        if (*reinterpret_cast<const DWORD*>(base + ntOffset) != IMAGE_NT_SIGNATURE)
            return false;

        const auto fileHeader = reinterpret_cast<const IMAGE_FILE_HEADER*>(base + ntOffset + sizeof(DWORD));
        const DWORD optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        if (fileHeader->SizeOfOptionalHeader < sizeof(WORD) ||
            optionalOffset > fileSize || fileSize - optionalOffset < fileHeader->SizeOfOptionalHeader)
            return false;

        const WORD sectionCount = fileHeader->NumberOfSections;
        if (sectionCount > 96)
            return false;

        const DWORD sectionOffset = optionalOffset + fileHeader->SizeOfOptionalHeader;
        const DWORD sectionBytes = static_cast<DWORD>(sectionCount) * static_cast<DWORD>(sizeof(IMAGE_SECTION_HEADER));
        if (sectionOffset > fileSize || fileSize - sectionOffset < sectionBytes)
            return false;

        const WORD magic = *reinterpret_cast<const WORD*>(base + optionalOffset);
        ImageDirectories directories;
        if (!ReadDirectories(base + optionalOffset, magic, fileHeader->SizeOfOptionalHeader, directories))
            return false;

        const auto sections = reinterpret_cast<const IMAGE_SECTION_HEADER*>(base + sectionOffset);
        const DWORD descriptorSize = static_cast<DWORD>(sizeof(IMAGE_IMPORT_DESCRIPTOR));

        if (directories.importRva != 0)
        {
            for (DWORD index = 0; index < 4096; ++index)
            {
                if (directories.importSize != 0 && (index + 1) * descriptorSize > directories.importSize)
                    break;
                if (index > (MAXDWORD - directories.importRva) / descriptorSize)
                    break;

                const DWORD rva = directories.importRva + index * descriptorSize;
                const auto descriptor = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(
                    RvaToPtr(base, fileSize, sections, sectionCount, rva, descriptorSize));
                if (descriptor == nullptr || descriptor->Name == 0)
                    break;

                AddDllName(base, fileSize, sections, sectionCount, descriptor->Name, DllRefSource::Import, vImports);
            }
        }

        const DWORD delaySize = static_cast<DWORD>(sizeof(DelayLoadDescriptor));
        if (directories.delayRva != 0)
        {
            for (DWORD index = 0; index < 4096; ++index)
            {
                if (directories.delaySize != 0 && (index + 1) * delaySize > directories.delaySize)
                    break;
                if (index > (MAXDWORD - directories.delayRva) / delaySize)
                    break;

                const DWORD rva = directories.delayRva + index * delaySize;
                const auto descriptor = reinterpret_cast<const DelayLoadDescriptor*>(
                    RvaToPtr(base, fileSize, sections, sectionCount, rva, delaySize));
                if (descriptor == nullptr)
                    break;
                if (descriptor->DllNameRVA == 0 && descriptor->ImportNameTableRVA == 0)
                    break;

                const DWORD nameRva = DelayNameRva(descriptor, directories.imageBase);
                if (nameRva != 0)
                    AddDllName(base, fileSize, sections, sectionCount, nameRva, DllRefSource::DelayImport, vImports);
            }
        }

        return true;
    }
}

ESTATUS GetPeImports(const string& sPath, vector<ImportRef>& vImports)
{
    vImports.clear();

    MappedFile mapped;
    if (!mapped.Open(sPath))
        return ESTATUS_INVALID;

    if (!ParseImports(mapped.base, mapped.size, vImports))
    {
        vImports.clear();
        return ESTATUS_INVALID;
    }

    return ESTATUS_SUCCESS;
}
