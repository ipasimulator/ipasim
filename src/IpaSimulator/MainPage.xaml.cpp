//
// MainPage.xaml.cpp
// Implementation of the MainPage class.
//

#include "pch.h"
#include "MainPage.xaml.h"
#include "invokes.h"
#include <LIEF/LIEF.hpp>
#include <LIEF/filesystem/filesystem.h>
#include <sstream>
#include <unicorn/unicorn.h>
#include <memory>
#include <map>

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

#if 0
/* Sample code to demonstrate how to emulate ARM code */

// code to be emulated
#define ARM_CODE "\x37\x00\xa0\xe3\x03\x10\x42\xe0" // mov r0, #0x37; sub r1, r2, r3
#define THUMB_CODE "\x83\xb0" // sub    sp, #0xc

// memory address where emulation starts
#define ADDRESS 0x10000

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing basic block at 0x%llx, block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%llx, instruction size = 0x%x\n", address, size);
}

static void test_arm(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int r0 = 0x1234;     // R0 register
    int r2 = 0x6789;     // R1 register
    int r3 = 0x3333;     // R2 register
    int r1;     // R1 register

    printf("Emulate ARM code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
            err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, ARM_CODE, sizeof(ARM_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM_REG_R0, &r0);
    uc_reg_write(uc, UC_ARM_REG_R2, &r2);
    uc_reg_write(uc, UC_ARM_REG_R3, &r3);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    err = uc_emu_start(uc, ADDRESS, ADDRESS + sizeof(ARM_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_R0, &r0);
    uc_reg_read(uc, UC_ARM_REG_R1, &r1);
    printf(">>> R0 = 0x%x\n", r0);
    printf(">>> R1 = 0x%x\n", r1);

    uc_close(uc);
}

static void test_thumb(void)
{
    uc_engine *uc;
    uc_err err;
    uc_hook trace1, trace2;

    int sp = 0x1234;     // R0 register

    printf("Emulate THUMB code\n");

    // Initialize emulator in ARM mode
    err = uc_open(UC_ARCH_ARM, UC_MODE_THUMB, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
            err, uc_strerror(err));
        return;
    }

    // map 2MB memory for this emulation
    uc_mem_map(uc, ADDRESS, 2 * 1024 * 1024, UC_PROT_ALL);

    // write machine code to be emulated to memory
    uc_mem_write(uc, ADDRESS, THUMB_CODE, sizeof(THUMB_CODE) - 1);

    // initialize machine registers
    uc_reg_write(uc, UC_ARM_REG_SP, &sp);

    // tracing all basic blocks with customized callback
    uc_hook_add(uc, &trace1, UC_HOOK_BLOCK, hook_block, NULL, 1, 0);

    // tracing one instruction at ADDRESS with customized callback
    uc_hook_add(uc, &trace2, UC_HOOK_CODE, hook_code, NULL, ADDRESS, ADDRESS);

    // emulate machine code in infinite time (last param = 0), or when
    // finishing all the code.
    // Note we start at ADDRESS | 1 to indicate THUMB mode.
    err = uc_emu_start(uc, ADDRESS | 1, ADDRESS + sizeof(THUMB_CODE) - 1, 0, 0);
    if (err) {
        printf("Failed on uc_emu_start() with error returned: %u\n", err);
    }

    // now print out some registers
    printf(">>> Emulation done. Below is the CPU context\n");

    uc_reg_read(uc, UC_ARM_REG_SP, &sp);
    printf(">>> SP = 0x%x\n", sp);

    uc_close(uc);
}
#endif

// from https://stackoverflow.com/a/23152590/9080566
template<class T> inline T operator~ (T a) { return (T)~(int)a; }
template<class T> inline T operator| (T a, T b) { return (T)((int)a | (int)b); }
template<class T> inline T operator& (T a, T b) { return (T)((int)a & (int)b); }
template<class T> inline T operator^ (T a, T b) { return (T)((int)a ^ (int)b); }
template<class T> inline T& operator|= (T& a, T b) { return (T&)((int&)a |= (int)b); }
template<class T> inline T& operator&= (T& a, T b) { return (T&)((int&)a &= (int)b); }
template<class T> inline T& operator^= (T& a, T b) { return (T&)((int&)a ^= (int)b); }

// from https://stackoverflow.com/a/27296/9080566
std::wstring s2ws(const std::string& s)
{
    int len;
    int slength = (int)s.length() + 1;
    len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
    wchar_t* buf = new wchar_t[len];
    MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
    std::wstring r(buf);
    delete[] buf;
    return r;
}

#define UC(arg) if (arg) { throw 1; }

class DynamicLoader {
public:
    DynamicLoader(unique_ptr<FatBinary>&& fat, const Binary& bin, uc_engine *uc) : fat_(move(fat)), bin_(bin), uc_(uc), libs_(), odd_addrs_() {}
    DynamicLoader(DynamicLoader&& dl) : fat_(move(dl.fat_)), bin_(move(dl.bin_)), uc_(dl.uc_), libs_(move(dl.libs_)), odd_addrs_(move(dl.odd_addrs_)) {}
    ~DynamicLoader() = default;

    static DynamicLoader create(const string& path, uc_engine *uc) {
        unique_ptr<FatBinary> fat(Parser::parse(path));
        Binary& bin = fat->at(0); // TODO: select correct binary more intelligently
        return DynamicLoader(move(fat), bin, uc);
    }
    void execute() {
        load();

        // TODO: unload LIEF's data from memory as they are not needed anymore

        // init stack
        size_t stacksize = 8 * 1024 * 1024; // 8 MiB
        void *stackmem = _aligned_malloc(stacksize, 4096);
        UC(uc_mem_map_ptr(uc_, (uint64_t)stackmem, stacksize, UC_PROT_READ | UC_PROT_WRITE, stackmem))
        uint32_t stacktop = (uint32_t)stackmem + stacksize - 12; // 12 bytes for 3 null arguments to the main procedure
        UC(uc_reg_write(uc_, UC_ARM_REG_SP, &stacktop))

        // debugging hooks
        uc_hook hook;
#define DEBUG_HOOKS
#ifdef DEBUG_HOOKS
        UC(uc_hook_add(uc_, &hook, UC_HOOK_CODE, hook_code, this, 1, 0))
#endif
        UC(uc_hook_add(uc_, &hook, UC_HOOK_MEM_FETCH_PROT, hook_mem_fetch_prot, this, 1, 0))

        // start execution
        UC(uc_emu_start(uc_, bin_.entrypoint() + slide_, 0, 0, 0))

        // cleanup
        UC(uc_close(uc_))
    }
    void load() {
        // check header info
        auto& header = bin_.header();
        if (header.file_type() != FILE_TYPES::MH_EXECUTE ||
            header.cpu_type() != CPU_TYPES::CPU_TYPE_ARM ||
            header.has(HEADER_FLAGS::MH_SPLIT_SEGS)) { // required by relocate_segment
            throw 1;
        }

        compute_slide();

        load_segments();

        process_bindings();

        // map libraries into the Unicorn Engine
        for (auto& lib : libs_) {
            uint64_t libLow = lib.second.first & (-4096);
            uint64_t libHigh = (lib.second.second + 4096) & (-4096);
            UC(uc_mem_map_ptr(uc_, libLow, libHigh - libLow, UC_PROT_READ | UC_PROT_WRITE, (void *)libLow))
        }
        libs_.clear();
    }
private:
#ifdef DEBUG_HOOKS
    static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
    {
        auto& dl = *(DynamicLoader *)user_data;
        OutputDebugStringA("executing at ");
        OutputDebugStringA(to_string(address - dl.slide_).c_str());
        uint32_t reg;
        UC(uc_reg_read(dl.uc_, UC_ARM_REG_PC, &reg))
        OutputDebugStringA(" PC = ");
        OutputDebugStringA(to_string(reg - dl.slide_).c_str());
        UC(uc_reg_read(dl.uc_, UC_ARM_REG_R12, &reg))
        OutputDebugStringA(" R12 = ");
        OutputDebugStringA(to_string(reg).c_str());
        OutputDebugStringA(" (");
        OutputDebugStringA(to_string(reg - dl.slide_).c_str());
        OutputDebugStringA(")\n");
    }
#endif
    static bool hook_mem_fetch_prot(uc_engine *uc, uc_mem_type type, uint64_t address, int size, int64_t value, void *user_data)
    {
        auto& dl = *(DynamicLoader *)user_data;

#ifndef ARM_HOST
        // fix odd address
        // TODO: don't even populate odd_addrs_ on ARM host
        if (dl.odd_addrs_.count(address)) {
            ++address;
        }
#endif

        // read emulated registers
#define READ_REG(num) uint32_t r##num; UC(uc_reg_read(uc, UC_ARM_REG_R##num, &r##num))

		READ_REG(0)
		READ_REG(1)
		READ_REG(2)
		READ_REG(3)
		READ_REG(13)
		READ_REG(14)
#undef READ_REG

		// execute target function using emulated cpu's context
		auto &name = dl.funcs_[address];
		if (!invokes::invoke(uc, address, name.c_str(), r0, r1, r2, r3, r13)) {
			throw "unrecognized function name";
		}

        // set result registers
#define WRITE_REG(num) UC(uc_reg_write(uc, UC_ARM_REG_R##num, &r##num))

        WRITE_REG(0)
        WRITE_REG(1)
        WRITE_REG(2)
        WRITE_REG(3)
#undef WRITE_REG

        // Move R14 (LR) value to R15 (PC) to return.
		UC(uc_reg_write(uc, UC_ARM_REG_R15, &r14))

        return true;
    }
    // inspired by ImageLoaderMachO::assignSegmentAddresses
    void compute_slide() {
        if (!canSegmentsSlide()) {
            throw 1;
        }

        // note: in mach-o, segments must slide together (see ImageLoaderMachO::segmentsMustSlideTogether)
        lowAddr_ = (uint64_t)(-1);
        highAddr_ = 0;
        for (auto& seg : bin_.segments()) {
            uint64_t segLow = seg.virtual_address();
            uint64_t segHigh = ((segLow + seg.virtual_size()) + 4095) & (-4096); // round to page size (as required by unicorn and what even dyld does)
            if (segLow < highAddr_) {
                throw "overlapping segments (after rounding to pagesize)";
            }
            if (segLow < lowAddr_) {
                lowAddr_ = segLow;
            }
            if (segHigh > highAddr_) {
                highAddr_ = segHigh;
            }
        }

        uintptr_t addr = (uintptr_t)_aligned_malloc(highAddr_ - lowAddr_, 4096);
        if (!addr) {
            throw 1;
        }
        slide_ = addr - lowAddr_;
    }
    // inspired by ImageLoaderMachO::mapSegments
    void load_segments() {
        for (auto& seg : bin_.segments()) {
            // convert protection
            auto vmprot = seg.init_protection();
            uc_prot perms = UC_PROT_NONE;
            if (vmprot & VM_PROTECTIONS::VM_PROT_READ) {
                perms |= UC_PROT_READ;
            }
            if (vmprot & VM_PROTECTIONS::VM_PROT_WRITE) {
                perms |= UC_PROT_WRITE;
            }
            if (vmprot & VM_PROTECTIONS::VM_PROT_EXECUTE) {
                perms |= UC_PROT_EXEC;
            }

            vaddr_ = unsigned(seg.virtual_address()) + slide_;
            uint8_t *mem = (uint8_t *)vaddr_; // emulated virtual address is actually equal to the "real" virtual address
            vsize_ = seg.virtual_size();

            if (perms == UC_PROT_NONE) {
                // no protection means we don't have to copy any data, we just map it
                UC(uc_mem_map_ptr(uc_, vaddr_, vsize_, perms, mem))
            }
            else {
                auto& buff = seg.content();
                memcpy(mem, buff.data(), buff.size()); // TODO: copy to the end of the allocated space if SG_HIGHVM flag is present
                UC(uc_mem_map_ptr(uc_, vaddr_, vsize_, perms, mem))

                // set the remaining memory to zeros
                if (buff.size() < vsize_) {
                    memset(mem + buff.size(), 0, vsize_ - buff.size());
                }
            }

            if (slide_ != 0) {
                relocate_segment(seg);
            }
        }
    }
    // inspired by ImageLoaderMachOClassic::rebase
    void relocate_segment(const LIEF::MachO::SegmentCommand& seg) {
        for (auto& rel : seg.relocations()) {
            if (rel.is_pc_relative() || rel.origin() != RELOCATION_ORIGINS::ORIGIN_DYLDINFO ||
                rel.size() != 32) {
                throw 1;
            }

            // find base address for this relocation
            // (inspired by ImageLoaderMachOClassic::getRelocBase)
            uint64_t relbase = unsigned(lowAddr_) + slide_;

            uint64_t reladdr = relbase + rel.address();
            uint32_t *val = (uint32_t *)reladdr;
            if (reladdr > vaddr_ + vsize_) {
                throw "relocation target out of range";
            }
            *val = unsigned(*val) + slide_;
        }
    }
    void process_bindings()
    {
        for (auto& binfo : bin_.dyld_info().bindings()) {
            binfo_ = &binfo;
            if ((binfo_->binding_class() != BINDING_CLASS::BIND_CLASS_STANDARD &&
                binfo_->binding_class() != BINDING_CLASS::BIND_CLASS_LAZY) ||
                binfo_->binding_type() != BIND_TYPES::BIND_TYPE_POINTER ||
                binfo_->addend()) {
                throw 1;
            }
            auto& lib = binfo.library();

            // find .dll
            string imp = lib.name();
            string sysprefix("/System/Library/Frameworks/");
            if (imp.substr(0, sysprefix.length()) == sysprefix) {
                string fwsuffix(".framework/");
                size_t i = imp.find(fwsuffix);
                string fwname = imp.substr(i + fwsuffix.length());
                if (i != string::npos && imp.substr(sysprefix.length(), i - sysprefix.length()) == fwname) {
                    if (fwname == "CoreFoundation") {
                        try_load_dll("CoreFoundation.dll") ||
                            load_dll("Foundation.dll");
                    }
                    else {
                        load_dll(fwname + ".dll");
                    }
                }
                else {
                    throw 1;
                }
            }
            else if (imp == "/usr/lib/libobjc.A.dylib") {
                try_load_dll("Foundation.dll") ||
                    load_dll("libobjc2.dll");
            }
            else if (imp == "/usr/lib/libSystem.B.dylib") {
                try_load_dll("libobjc2.dll") ||
                    try_load_dll("libdispatch.dll") ||
                    load_dll("ucrtbased.dll");
            }
            else {
                throw 1;
            }
        }
    }
    bool load_dll(const string& name) {
        if (!try_load_dll(name)) {
            throw 1;
        }
        return true;
    }
    bool try_load_dll(const string& name) {
        // load .dll
        auto winlib = LoadPackagedLibrary(s2ws(name).c_str(), 0);
        if (!winlib) {
            throw "library " + name + " couldn't be loaded";
        }

        // translate symbol name
        // ---------------------
        string n = binfo_->symbol().name();

        // remove leading underscore
        if (n.length() != 0 && n[0] == '_') {
            n = n.substr(1);
        }

        // translate class names
        string cprefix("OBJC_CLASS_$_");
        if (n.substr(0, cprefix.length()) == cprefix) {
            n = "_OBJC_CLASS_" + n.substr(cprefix.length());
        }

        // TODO: instead of ignoring, set them to NULL or some catch-all handler (for functions)?
        // ignore metaclasses
        // TODO: or are they the objc_class_name things?
        string mcprefix("OBJC_METACLASS_$_");
        if (n.substr(0, mcprefix.length()) == mcprefix) {
            return true;
        }

        // ignore non-existing symbols (it is observed that they are used only in exports, so it shouldn't matter)
        if (n == "_objc_empty_cache") {
            return true;
        }

        // TODO: don't ignore these, implement them!
        if (n == "objc_msgSendSuper2" ||
            n == "dyld_stub_binder" ||
            n == "__CFConstantStringClassReference") { // defined in CFInternal.h
            return true;
        }
        // ---------------------

        // get symbol address
        auto addr = GetProcAddress(winlib, n.c_str());
        if (!addr) {
            return false;
        }

        uint64_t iaddr = (uint64_t)addr;
        if (iaddr % 2) {
            odd_addrs_.insert(iaddr - 1);
            // TODO: maybe also check that there are no (iaddr-1) values bound to avoid ambiguity
        }

		// Remember the function's name.
		funcs_[iaddr] = n;

        auto lib = libs_.find(name);
        if (lib == libs_.end()) {
            libs_[name] = make_pair(iaddr, iaddr);
        }
        else {
            if (lib->second.first > iaddr) {
                lib->second.first = iaddr;
            }
            if (lib->second.second > iaddr) {
                lib->second.second = iaddr;
            }
        }

        // rewrite stub address with the found one
        bind_to((intptr_t)addr);
        return true;
    }
    void bind_to(uintptr_t addr) {
        uint64_t target = unsigned(binfo_->address()) + slide_;
        if (target < unsigned(lowAddr_) + slide_ ||
            target >= unsigned(highAddr_) + slide_) {
            throw "binding target out of range";
        }
        *((uint32_t *)target) = addr;
    }
    // inspired by ImageLoaderMachO::segmentsCanSlide
    bool canSegmentsSlide() {
        auto ftype = bin_.header().file_type();
        return ftype == FILE_TYPES::MH_DYLIB ||
            ftype == FILE_TYPES::MH_BUNDLE ||
            (ftype == FILE_TYPES::MH_EXECUTE && bin_.is_pie());
    }

    unique_ptr<FatBinary> fat_;
    const Binary& bin_;
    uc_engine *uc_;
    const BindingInfo *binfo_;
    int64_t slide_;
    uint64_t vaddr_, vsize_;
    uint64_t lowAddr_, highAddr_;
    map<string, pair<uint64_t, uint64_t>> libs_; // libraries' low and high addresses
    set<uint64_t> odd_addrs_; // all bound addresses that are odd, but inserted decremented by 1 (so even)
	map<uint64_t, string> funcs_; // map from function addresses to their names
};

MainPage::MainPage()
{
    InitializeComponent();

    // initialize unicorn engine
    uc_engine *uc;
    UC(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &uc))

    // load test Mach-O binary
    filesystem::path dir(ApplicationData::Current->TemporaryFolder->Path->Data());
    filesystem::path file("test.ipa");
    filesystem::path full = dir / file;
    DynamicLoader::create(full.str(), uc).execute();

    UC(uc_close(uc))
}
