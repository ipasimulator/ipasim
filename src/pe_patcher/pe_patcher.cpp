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

    // Create `.mhdr` section.
    LIEF::PE::Section mhdrSection;
    mhdrSection.name(".mhdr");
    const char *data = "Hello, .mhdr section!";
    mhdrSection.content(vector<uint8_t>(data, data + strlen(data)));
    mhdrSection = binary->add_section(mhdrSection, LIEF::PE::PE_SECTION_TYPES::DATA);

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
    //binary->write(string(argv[1]) + "-edit.exe");

    LIEF::PE::Builder builder(binary.get());
    builder.build();
    builder.write(string(argv[1]) + "-edit.exe");

    LIEF::PE::Binary patched(binary->name(), binary->type());

    cout << "Done" << endl;
    return 0;
}
