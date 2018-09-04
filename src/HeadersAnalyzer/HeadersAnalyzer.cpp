// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <fstream>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/Utils.h>
#include <clang/Basic/TargetOptions.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Driver/Driver.h>
#include <clang/Lex/PreprocessorOptions.h>
#include <clang/Parse/ParseAST.h>
#include <clang/AST/Type.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <llvm/Demangle/Demangle.h>
#include <tapi/Core/FileManager.h>
#include <tapi/Core/InterfaceFile.h>
#include <tapi/Core/InterfaceFileManager.h>
#include <filesystem>
#include <vector>

using namespace clang;
using namespace frontend;
using namespace std;
using namespace experimental::filesystem;
using namespace tapi::internal;

struct export_entry {
    set<string> libs;
    string mangledName;
};

// Key is demangled symbol name.
using export_list = map<string, export_entry>;

class HeadersAnalyzer {
public:
    HeadersAnalyzer(CompilerInstance &ci, export_list &exps, ostream &output) : ci_(ci), exps_(exps),
        after_first_(false), output_(output) {}
    void Initialize() {}
    void HandleTopLevelDecl(DeclGroupRef d) {}
    void VisitFunction(FunctionDecl &f) {
        string name = f.getNameAsString();

        // Skip functions that do not interest us.
        auto it = exps_.find(name);
        if (it == exps_.end()) { return; }

        // We cannot handle varargs functions for now.
        // TODO: Handle varargs functions.
        if (f.isVariadic()) {
            cerr << "vararg function found: " << name << endl;
            return;
        }

        auto fpt = static_cast<const FunctionProtoType *>(f.getFunctionType());

        // Ignore templates.
        if (fpt->isDependentType()) { return; }

        // TODO: check that the function is actually exported from the corresponding
        // .dylib file (it's enough to check .tbd file inside the SDK which is simply
        // a YAML)
        //YAML::LoadFile("test.yaml");
        // TODO: maybe use LLVM YAML I/O library instead (http://llvm.org/docs/YamlIO.html)

        // TODO: also check that the function has the same signature in WinObjC headers
        // inside the (NuGet) packages folder

        if (after_first_) {
            output_ << "else ";
        }
        else {
            after_first_ = true;
        }
        // TODO: Don't compare `module` with symbol name!
        output_ << "if (!std::strcmp(module, \"" << name << "\")) {" << endl;

        // We will simply assume arguments are in r0-r3 or on stack for starters.
        // Inspired by /res/IHI0042F_aapcs.pdf (AAPCS), section 5.5 Parameter Passing.

        uint8_t r = 0; // register offset (AAPCS's NCRN)
        uint64_t s = 0; // stack offset (relative AAPCS's NSAA)

        uint32_t i = 0;
        for (auto &pt : fpt->param_types()) {
            uint64_t bytes = ci_.getASTContext().getTypeSizeInChars(pt).getQuantity();

            output_ << "ARG(" << to_string(i) << ", " << pt.getAsString() << ")" << endl;

            // Copy data from registers and/or stack into the argument.
            if (r == 4) {
                // We used all the registers, this argument is on the stack.
                // Note that r13 is the stack pointer.
                // TODO: Handle unicorn errors.
                // TODO: Encapsulate this into a macro.
                // TODO: Maybe read the memory at the SP directly.
                output_ << "uc_mem_read(uc, r13, c" << to_string(i) << " + " << to_string(s) << ", " << to_string(bytes) << ");" << endl;
                s += bytes;
            }
            else {
                assert(bytes > 0 && "non-trivial type expected");
                assert(bytes <= 64 && "we can only handle max. 64-byte-long data for now");

                for (;;) {
                    output_ << "p" << to_string(i) << "[" << to_string(r) << "] = r" << to_string(r) << ";" << endl;
                    ++r;

                    if (bytes <= 4) { break; }
                    bytes -= 4;
                }
            }

            ++i;
        }

        // Call the function through a function pointer saved in argument named "address".
        auto pt = ci_.getASTContext().getPointerType(QualType(fpt, 0)); // TODO: How to properly create QualType?
        if (!fpt->getReturnType()->isVoidType()) { output_ << "RET("; }
        output_ << "reinterpret_cast<" << pt.getAsString() << ">(address)(";
        for (i = 0; i != fpt->getNumParams(); ++i) {
            if (i != 0) { output_ << ", "; }
            output_ << "*v" << to_string(i);
        }
        if (!fpt->getReturnType()->isVoidType()) { output_ << ")"; }
        output_ << ");" << endl;

        // Handle the return value.
        if (!fpt->getReturnType()->isVoidType()) {
            r = 0;
            uint64_t bytes = toBytes(ci_.getASTContext().getTypeSize(fpt->getReturnType()));
            assert(bytes > 0 && "non-trivial return type expected");
            assert(bytes <= 64 && "we can only handle max. 64-byte-long data for now");

            for (;;) {
                output_ << "r" << to_string(r) << " = retp[" << to_string(r) << "];" << endl;
                ++r;

                if (bytes <= 4) { break; }
                bytes -= 4;
            }
        }

        output_ << "}" << endl;
    }
private:
    bool after_first_;
    CompilerInstance &ci_;
    export_list &exps_;
    ostream &output_;

    uint64_t toBytes(uint64_t bits) {
        assert(bits % 8 == 0 && "whole bytes expected");
        return bits / 8;
    }
};

class CustomASTVisitor : public RecursiveASTVisitor<CustomASTVisitor> {
public:
    CustomASTVisitor(HeadersAnalyzer &ha) : ha_(ha) {}
    bool VisitFunctionDecl(FunctionDecl *f) { // TODO: override
        // TODO: Should we call parent's implementation?
        //if (!RecursiveASTVisitor::VisitFunctionDecl(f)) { return false; }

        ha_.VisitFunction(*f);
        return true;
    }
private:
    HeadersAnalyzer & ha_;
};

class CustomASTConsumer : public ASTConsumer {
public:
    CustomASTConsumer(HeadersAnalyzer &ha) : v_(ha), ha_(ha) {}
    bool HandleTopLevelDecl(DeclGroupRef d) override {
        ha_.HandleTopLevelDecl(d);
        // TODO: move the following code into the HandleTopLevelDecl function
        for (auto b : d) {
            v_.TraverseDecl(b);
        }
        return true;
    }
private:
    CustomASTVisitor v_;
    HeadersAnalyzer &ha_;
};

class tbd_handler {
public:
    tbd_handler(export_list &exps) : exps_(exps), fm_(FileSystemOptions()), ifm_(fm_) {}
    void handle_tbd_file(const string &path) {
        // Check file.
        auto fileOrError = ifm_.readFile(path);
        if (!fileOrError) {
            cerr << "Error: " << llvm::toString(fileOrError.takeError()) << " (" << path << ")." << endl;
            return;
        }
        auto file = *fileOrError;
        if (!file->getArchitectures().contains(Architecture::armv7)) {
            cerr << "TBD file does not contain architecture ARMv7 (" << path << ")." << endl;
            return;
        }
        auto ifile = dynamic_cast<InterfaceFile *>(file);
        if (!ifile) {
            cerr << "Interface file expected (" << path << ")." << endl;
            return;
        }
        cout << "Found TBD file (" << path << ")." << endl;

        // Find exports.
        for (auto sym : ifile->exports()) {
            // Determine symbol name.
            string mangled, demangled;
            switch (sym->getKind()) {
            case SymbolKind::ObjectiveCClass:
                mangled = ("_OBJC_CLASS_$" + sym->getName()).str();
                demangled = ("OBJC_CLASS_$" + sym->getName()).str();
                break;
            case SymbolKind::ObjectiveCInstanceVariable:
                mangled = ("_OBJC_IVAR_$" + sym->getName()).str();
                demangled = ("OBJC_IVAR_$" + sym->getName()).str();
                break;
            case SymbolKind::ObjectiveCClassEHType:
                mangled = ("_OBJC_EHTYPE_$_" + sym->getName()).str();
                demangled = ("OBJC_EHTYPE_$_" + sym->getName()).str();
                break;
            case SymbolKind::GlobalSymbol:
                mangled = sym->getPrettyName(/* demangle: */ false);
                demangled = sym->getPrettyName(/* demangle: */ true);
                break;
            default:
                cerr << "Unrecognized symbol type (" << sym->getAnnotatedName() << ")." << endl;
                continue;
            }

            // Save export.
            auto it = exps_.find(demangled);
            if (it != exps_.end()) {
                it->second.libs.insert(ifile->getInstallName());
            }
            else {
                exps_[demangled] = export_entry{ /* libs: */ { ifile->getInstallName() }, mangled };
            }
        }
    }
private:
    export_list &exps_;
    tapi::internal::FileManager fm_;
    InterfaceFileManager ifm_;
};

int main()
{
    export_list exps;

    // Discover `.tbd` files.
    {
        tbd_handler tbdh(exps);
        vector<string> tbdDirs{
            "./deps/apple-headers/iPhoneOS11.1.sdk/usr/lib/",
            "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/TextInput/"
        };
        for (auto&& dir : tbdDirs) {
            for (auto&& file : directory_iterator(dir)) {
                tbdh.handle_tbd_file(file.path().string());
            }
        }
        // Discover `.tbd` files inside frameworks.
        string frameworksDir = "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/Frameworks/";
        for (auto&& entry : directory_iterator(frameworksDir)) {
            if (entry.status().type() == file_type::directory &&
                !entry.path().extension().compare(".framework")) {
                tbdh.handle_tbd_file((entry.path() / entry.path().filename().replace_extension(".tbd")).string());
            }
        }
        cout << endl;
    }

    // Create output files.
    // TODO: This won't create the /out/ directory if it doesn't exist!
    fstream invokes("./out/invokes.inc", fstream::out);
    fstream headers("./out/headers.inc", fstream::out);

    // Analyze headers.
    vector<string> headerPaths{
        "./deps/WinObjC/include/Foundation/Foundation.h",
        "./deps/WinObjC/tools/include/objc/objc-arc.h",
        "./deps/WinObjC/tools/include/objc/message.h"
    };
    for (auto &headerPath : headerPaths) {
        headers << "#include \"" << headerPath << "\"" << endl;
        cout << headerPath << endl;

        // Originally inspired by https://github.com/loarabia/Clang-tutorial/.
        // TODO: move this to a separate class

        CompilerInstance ci;
        ci.createDiagnostics();
        ci.getDiagnostics().setIgnoreAllWarnings(true);

        vector<const char *> args{
            "-target=i386-pc-windows-msvc",
            "-std=c++14",
            "-fblocks",
            "-fobjc-runtime=macosx-10.13.0",
            "-DOBJC_PORT",
            "-DNOMINMAX",
            "-DWIN32_LEAN_AND_MEAN",
            "-I", "./deps/WinObjC/include",
            "-I", "./deps/WinObjC/include/Platform/Universal Windows",
            "-I", "./deps/WinObjC/Frameworks/include",
            "-I", "./deps/WinObjC/include/xplat",
            "-I", "./deps/WinObjC/tools/include/WOCStdLib",
            "-I", "./deps/WinObjC/tools/include",
            "-I", "./deps/WinObjC/tools/Logging/include",
            "-I", "./deps/WinObjC/tools/include/xplat",
            "-I", "./deps/WinObjC/tools/deps/prebuilt/include",
            "-x", "objective-c++",
            headerPath.c_str()
        };
        ci.setInvocation(createInvocationFromCommandLine(llvm::makeArrayRef(args)));

        // TODO: TargetInfo* should be deleted when not needed anymore. Should it, though?
        ci.setTarget(TargetInfo::CreateTargetInfo(ci.getDiagnostics(), ci.getInvocation().TargetOpts));

        ci.createFileManager();
        ci.createSourceManager(ci.getFileManager());

        //ci.getPreprocessorOpts().UsePredefines = false;
        ci.createPreprocessor(TranslationUnitKind::TU_Complete);
        HeadersAnalyzer ha(ci, exps, invokes);
        ci.setASTConsumer(make_unique<CustomASTConsumer>(ha));
        ci.createASTContext();
        ha.Initialize();
        ci.createSema(TranslationUnitKind::TU_Complete, nullptr);

        const auto file = ci.getFileManager().getFile(headerPath);
        ci.getSourceManager().setMainFileID(ci.getSourceManager().createFileID(file, SourceLocation(), SrcMgr::C_User));

        ci.getDiagnosticClient().BeginSourceFile(ci.getLangOpts(), &ci.getPreprocessor());
        ParseAST(ci.getSema(), /*PrintStats*/ false, /*SkipFunctionBodies*/ true);
        ci.getDiagnosticClient().EndSourceFile();
    }

    return 0;
}
