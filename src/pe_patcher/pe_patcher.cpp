// pe_patcher.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"

using namespace std;

int main(int argc, char** argv)
{
    if (argc != 2) {
        cerr << "Usage: " << argv[0] << " <binary>" << endl;

        // Pause.
        getc(stdin);
        return 1;
    }

    std::unique_ptr<LIEF::PE::Binary> binary = LIEF::PE::Parser::parse(argv[1]);

    // Find the lowest virtual address used.
    uint64_t va = numeric_limits<uint64_t>::max();
    for (auto &&section : binary->sections()) {
        uint64_t sva = section.virtual_address();
        if (sva < va) { va = sva; }
    }

    // Create `.mhdr` section.
    LIEF::PE::Section mhdrSection;
    mhdrSection.name(".mhdr");

    // Set its content.
    const char *data = "Hello, .mhdr section!";
    uint64_t size = strlen(data);
    mhdrSection.content(vector<uint8_t>(data, data + size));

    // Set its RVA.
    // TODO: Changing virtual_address makes the resulting PE binary invalid. Why?
    //mhdrSection.virtual_address(va - size); // TODO: Check that it's non-negative.
    //mhdrSection.virtual_address(0x34000 << 2);

    // Set its characteristics.
    mhdrSection.characteristics_list().clear();
    mhdrSection.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_CNT_INITIALIZED_DATA);
    mhdrSection.add_characteristic(LIEF::PE::SECTION_CHARACTERISTICS::IMAGE_SCN_MEM_READ);

    mhdrSection = binary->add_section(mhdrSection);

    // Remove some flags. TODO: Probably not needed.
    binary->optional_header().dll_characteristics_list().erase(LIEF::PE::DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_DYNAMIC_BASE);
    binary->optional_header().dll_characteristics_list().erase(LIEF::PE::DLL_CHARACTERISTICS::IMAGE_DLL_CHARACTERISTICS_NX_COMPAT);

    // Save the binary.
    binary->write(string(argv[1]) + "-edit.exe");

    // Move the `.mhdr` section to the top.
    // TODO: It doesn't seem to be working.
    /*auto start = binary->sections();
    auto it = --binary->sections().end();
    assert(*it == mhdrSection);
    for (; it != start;) {
        auto curr = it--;
        swap(*it, *curr);
    }*/

    // TODO: Rebuild the binary (maybe also rearrange the sections to group them into segments).
    //LIEF::PE::Builder builder(binary.get());
    //builder.build_imports(true);
    //builder.patch_imports(true);
    //

    /*LIEF::PE::Builder builder(binary.get());
    builder.build();
    builder.write(string(argv[1]) + "-edit.exe");

    LIEF::PE::Binary patched(binary->name(), binary->type());*/

    cout << "Done" << endl;
    return 0;
}
