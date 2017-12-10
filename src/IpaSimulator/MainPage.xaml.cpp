//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include <LIEF/LIEF.hpp>
#include <LIEF/filesystem/filesystem.h>
#include <sstream>
#include <unicorn/unicorn.h>

using namespace IpaSimulator;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::Storage;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;
using namespace std;
using namespace LIEF::MachO;

MainPage::MainPage()
{
	InitializeComponent();

    filesystem::path dir(ApplicationData::Current->TemporaryFolder->Path->Data());
    filesystem::path file("todo.ipa");
    filesystem::path full = dir / file;
    FatBinary* fat = Parser::parse(full.str()); // TODO: maybe convert to unique_ptr
    Binary& bin = fat->at(0);
#if 0
    for (auto& c : bin.commands()) {
        uint32_t s = c.size();
        buffer_t b = c.data();
    }
#endif
    delete fat;

#define X86_CODE32 "\x41\x4a"
#define ADDRESS 0x1000000
    uc_engine *uc;
    uc_err err;
    int r_ecx = 0x1234;     // ECX register
    int r_edx = 0x7890;     // EDX register
    
    printf("Emulate i386 code\n");
    
    // Initialize emulator in X86-32bit mode
    err = uc_open(UC_ARCH_X86, UC_MODE_32, &uc);
    if (err != UC_ERR_OK) {
      printf("Failed on uc_open() with error returned: %u\n", err);
      return;
    }
    
    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);
    
    // write machine code to be emulated to memory
    if (uc_mem_write(uc, ADDRESS, X86_CODE32, sizeof(X86_CODE32) - 1)) {
      printf("Failed to write emulation code to memory, quit!\n");
      return;
    }
    
    // initialize machine registers
    uc_reg_write(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_write(uc, UC_X86_REG_EDX, &r_edx);
    
    // emulate code in infinite time & unlimited instructions
    err=uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(X86_CODE32) - 1, 0, 0);
    if (err) {
      printf("Failed on uc_emu_start() with error returned %u: %s\n",
        err, uc_strerror(err));
    }
    
    // now print out some registers
    printf("Emulation done. Below is the CPU context\n");
    
    uc_reg_read(uc, UC_X86_REG_ECX, &r_ecx);
    uc_reg_read(uc, UC_X86_REG_EDX, &r_edx);
    printf(">>> ECX = 0x%x\n", r_ecx);
    printf(">>> EDX = 0x%x\n", r_edx);
    
    uc_close(uc);
}
