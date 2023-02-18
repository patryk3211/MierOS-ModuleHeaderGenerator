#include <algorithm>
#include <cstdint>
#include <stdexcept>
#include <iostream>
#include <elfio/elfio.hpp>
#include <vector>
#include <list>
#include <nlohmann/json.hpp>

//
// Usage:
// modhdrgen <module_manifest> <output_file>
//

using namespace ELFIO;
using namespace nlohmann;

static std::vector<uint8_t> s_data;
static relocation_section_accessor* s_relocations;

#define MODHDR_SECTION_IDX 2
#define SYMTAB_SECTION_IDX 4
#define STRTAB_SECTION_IDX 5

#define MODHDR_SYMBOL_IDX 1

#define MODULE_MAGIC (uint64_t) \
    (uint64_t) 0x7F << 0  |     \
    (uint64_t) 'M'  << 8  |     \
    (uint64_t) 'O'  << 16 |     \
    (uint64_t) 'D'  << 24 |     \
    (uint64_t) 'H'  << 32 |     \
    (uint64_t) 'D'  << 40 |     \
    (uint64_t) 'R'  << 48 |     \
    (uint64_t) '1'  << 56

template<typename T> Elf64_Addr add_value(const T& value, std::vector<uint8_t>& storage = s_data) {
    Elf64_Addr offset = s_data.size();
    s_data.resize(offset + sizeof(T));
    memcpy(s_data.data() + offset, &value, sizeof(T));
    return offset;
}

Elf64_Addr add_string(const std::string& value) {
    Elf64_Addr offset = s_data.size();
    s_data.insert(s_data.end(), value.begin(), value.end());
    s_data.push_back(0);

    return offset;
}

void add_array_entry(Elf64_Addr value) {
    Elf64_Addr offset = add_value(value);
    s_relocations->add_entry(offset, MODHDR_SYMBOL_IDX, R_X86_64_64, value);
}

Elf64_Addr add_string_array(const std::list<std::string>& values) {
    std::list<Elf64_Addr> addresses;
    for(auto& str : values)
        addresses.push_back(add_string(str));

    // Make the pointer array aligned to 16 bytes
    if(s_data.size() & 0xF)
        s_data.resize((s_data.size() | 0xF) + 1);
    
    Elf64_Addr offset = s_data.size();
    std::for_each(addresses.begin(), addresses.end(), add_array_entry);
    add_value<Elf64_Addr>(0); // Terminate the array
    return offset;
}

int main(int argc, char* argv[]) {
    if(argc != 3) {
        std::cerr << "Usage:\n  " << argv[0] << " <module_manifest> <output_file>" << std::endl;
        return 1;
    }

    elfio writer;
    writer.create(ELFCLASS64, ELFDATA2LSB);

    writer.set_os_abi(ELFOSABI_NONE);
    writer.set_type(ET_REL);
    writer.set_machine(EM_X86_64);

    // Create sections
    section* modHdr = writer.sections.add(".modulehdr");
    modHdr->set_type(SHT_PROGBITS);
    modHdr->set_flags(SHF_ALLOC);
    modHdr->set_addr_align(0x10);

    section* modHdrRela = writer.sections.add(".rela.modulehdr");
    modHdrRela->set_type(SHT_RELA);
    modHdrRela->set_flags(SHF_INFO_LINK);
    modHdrRela->set_entry_size(0x18);
    modHdrRela->set_addr_align(0x08);
    modHdrRela->set_info(MODHDR_SECTION_IDX);
    modHdrRela->set_link(SYMTAB_SECTION_IDX);

    section* symTab = writer.sections.add(".symtab");
    symTab->set_type(SHT_SYMTAB);
    symTab->set_entry_size(0x18);
    symTab->set_addr_align(0x08);
    symTab->set_link(STRTAB_SECTION_IDX);
    symTab->set_info(2); // We have 2 local symbols for now

    section* strTab = writer.sections.add(".strtab");
    strTab->set_type(SHT_STRTAB);
    strTab->set_addr_align(1);

    // Create basic symbols
    symbol_section_accessor symbolAccessor(writer, symTab);
    string_section_accessor stringAccessor(strTab);

    symbolAccessor.add_symbol(stringAccessor, ".modulehdr", 0, 0, STB_LOCAL, STT_SECTION, STV_DEFAULT, MODHDR_SECTION_IDX);

    // Prepare relocation section for access
    relocation_section_accessor accessor(writer, modHdrRela);
    s_relocations = &accessor;

    // Build the module header
    std::vector<uint8_t> headerStorage;
    add_value(MODULE_MAGIC, headerStorage);

    try {
        std::ifstream manifestStream(argv[1]);
        json manifestJson = json::parse(manifestStream);

        { // First field is the module name
            std::string moduleName = manifestJson.at("name");
            if(moduleName.length() > 127)
                throw std::length_error("Module name exceeds 127 character limit");
            
            char tempStorage[128];
            memset(tempStorage, 0, sizeof(tempStorage));
            memcpy(tempStorage, moduleName.c_str(), moduleName.length());

            // Insert module name
            headerStorage.insert(headerStorage.end(), tempStorage, tempStorage + 128);
        }

        { // Handle dependencies
            std::list<std::string> depList;

            auto deps = manifestJson.at("dependencies");
            for(auto& dependency : deps) {
                auto depName = dependency.get<std::string>();
                depList.push_back(depName);
            }

            Elf64_Addr addr = add_string_array(depList);
            add_value(addr, headerStorage);
        }

        { // Handle aliases
            std::list<std::string> aliasList;

            auto aliases = manifestJson.at("aliases");
            for(auto& alias : aliases) {
                auto aliasStr = alias.get<std::string>();
                aliasList.push_back(aliasStr);
            }

            Elf64_Addr addr = add_string_array(aliasList);
            add_value(addr, headerStorage);
        }
    } catch(const std::exception& e) {
        std::cerr << "Module manifest parsing failed, what(): " << e.what();
        return 2;
    }

    // Add header symbol
    Elf64_Addr headerStart = s_data.size();
    s_data.insert(s_data.end(), headerStorage.begin(), headerStorage.end());
    symbolAccessor.add_symbol(stringAccessor, "__module_header", headerStart, headerStorage.size(),
                              STB_GLOBAL, STT_OBJECT, STV_DEFAULT, MODHDR_SECTION_IDX);

    modHdr->set_data((char*)s_data.data(), s_data.size());
    writer.save(argv[2]);
    return 0;
}

