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
#include <clang/AST/Mangle.h>
#include <clang/AST/Type.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/Support/raw_os_ostream.h>
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

enum class export_status {
    NotFound = 0,
    Found,
    Overloaded,
    Generated
};

struct export_entry {
    export_entry() : status(export_status::NotFound), type(nullptr) {}
    export_entry(string firstLib) : status(export_status::NotFound), type(nullptr) {
        libs.insert(move(firstLib));
    }

    set<string> libs;
    export_status status;
    const FunctionProtoType *type;
    string identifier;
};

// Key is symbol name.
using export_list = map<string, export_entry>;

class HeadersAnalyzer {
public:
    HeadersAnalyzer(CompilerInstance &ci, export_list &exps, ostream &output) : ci_(ci), exps_(exps),
        after_first_(false), output_(output), mctx_(nullptr) {}
    ~HeadersAnalyzer() {
        if (mctx_) {
            delete mctx_;
        }
    }
    void Initialize() {
        // TODO: Is this mangling what Apple uses?
        mctx_ = ItaniumMangleContext::create(ci_.getASTContext(), ci_.getDiagnostics());
    }
    void HandleTopLevelDecl(DeclGroupRef d) {}
    void VisitFunction(FunctionDecl &f) {
        auto fpt = static_cast<const FunctionProtoType *>(f.getFunctionType());

        // Ignore templates.
        if (fpt->isDependentType()) { return; }

        // Get function's mangled name. Inspired by
        // https://github.com/llvm-mirror/clang/blob/1bc73590ad1335313e8f262393547b8af67c9167/lib/Index/CodegenNameGenerator.cpp#L150.
        string name;
        if (mctx_->shouldMangleDeclName(&f)) {
            llvm::raw_string_ostream ostream(name);
            if (const auto *CtorD = dyn_cast<CXXConstructorDecl>(&f))
                mctx_->mangleCXXCtor(CtorD, Ctor_Complete, ostream);
            else if (const auto *DtorD = dyn_cast<CXXDestructorDecl>(&f))
                mctx_->mangleCXXDtor(DtorD, Dtor_Complete, ostream);
            else
                mctx_->mangleName(&f, ostream);
            ostream.flush();
        }
        else {
            // TODO: Even though our mangler says C functions shouldn't be mangled,
            // they seem to actually be mangled on iOS.
            if (f.getLanguageLinkage() == CLanguageLinkage) {
                name = "_";
            }
            name += f.getIdentifier()->getName().str();
        }

        // Skip functions that do not interest us.
        auto it = exps_.find(name);
        if (it == exps_.end()) {
            return;
        }

        // We cannot handle varargs functions for now.
        // TODO: Handle varargs functions.
        if (f.isVariadic()) {
            it->second.status = export_status::Overloaded;
            cerr << "Error: function is variadic (" << name << ")." << endl;
            return;
        }

        if (it->second.status != export_status::NotFound) {

            // Just skip it if it is exactly the same function or we already know it's overloaded.
            // TODO: Maybe just delete overloaded functions from `exps_`.
            if (it->second.status == export_status::Overloaded ||
                // TODO: Does this work?
                it->second.type->desugar() == fpt->desugar()) {
                return;
            }

            // Otherwise, it's an overloaded function and we can't support those.
            it->second.status = export_status::Overloaded;
            if (it->second.status == export_status::Generated) {
                // TODO: Such function was generated, but we must ignore it!
                cerr << "Fatal error: function is overloaded accross headers (" << name << ")." << endl;
            }
            else {
                cerr << "Error: function is overloaded (" << name << ")." << endl;
            }
            return;
        }
        it->second.status = export_status::Found;

        // TODO: Check that Apple's and WinObjC's signatures of the function are equal.

        // Save function type and identifier, needed later for code generation.
        // TODO: Won't this get deleted too early?
        it->second.type = fpt;
        it->second.identifier = f.getIdentifier()->getName().str();
    }
    void GenerateCode() {
        for (auto &&exp : exps_) {
            if (exp.second.status == export_status::Found) {
                exp.second.status = export_status::Generated;
                const string &name = exp.first;
                const FunctionProtoType *fpt = exp.second.type;

                // TODO: Don't do any of the following code, implement and use `cc_mapper` instead.

                if (after_first_) {
                    output_ << "else ";
                }
                else {
                    after_first_ = true;
                }
                // TODO: Don't compare `module` with symbol name!
                output_ << "if (!std::strcmp(module, \"" << name << "\")) {" << endl;

                // We will simply assume arguments are in r0-r3 or on stack for starters.
                // Inspired by /res/arm/IHI0042F_aapcs.pdf (AAPCS), section 5.5 Parameter Passing.

                uint8_t r = 0; // register offset (AAPCS's NCRN)
                uint64_t s = 0; // stack offset (relative AAPCS's NSAA)

                uint32_t i = 0;
                for (auto &pt : fpt->param_types()) {
                    uint64_t bytes = ci_.getASTContext().getTypeSizeInChars(pt).getQuantity();
                    assert(bytes > 0 && "non-trivial type expected");

                    output_ << "ARG(" << to_string(i) << ", " << pt.getAsString() << ")" << endl;

                    // Copy data from registers and/or stack into the argument.
                    while (bytes) {
                        if (r == 4) {
                            // We used all the registers, this argument is on the stack.
                            // Note that r13 is the stack pointer.
                            // TODO: Handle unicorn errors.
                            // TODO: Encapsulate this into a macro.
                            // TODO: Maybe read the memory at the SP directly.
                            output_ << "uc_mem_read(uc, r13, c" << to_string(i) << " + " << to_string(s) << ", " << to_string(bytes) << ");" << endl;
                            s += bytes;
                            break; // We copied all the data.
                        }
                        else {
                            output_ << "p" << to_string(i) << "[" << to_string(r) << "] = r" << to_string(r) << ";" << endl;
                            ++r;

                            if (bytes <= 4) { break; }
                            bytes -= 4;
                        }
                    }

                    ++i;
                }

                // Call the function through a function pointer saved in argument named "address".
                output_ << "using ft = decltype(" << exp.second.identifier << ");" << endl;
                if (!fpt->getReturnType()->isVoidType()) { output_ << "RET("; }
                output_ << "reinterpret_cast<ft *>(address)(";
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

                    for (;;) {
                        if (r == 4) {
                            output_ << "// TODO: Return value is too big!";
                        }
                        if (r >= 4) {
                            output_ << "// ";
                        }

                        output_ << "r" << to_string(r) << " = retp[" << to_string(r) << "];" << endl;
                        ++r;

                        if (bytes <= 4) { break; }
                        bytes -= 4;
                    }
                }

                output_ << "}" << endl;
            }
        }
    }
private:
    bool after_first_;
    CompilerInstance &ci_;
    export_list &exps_;
    ostream &output_;
    MangleContext *mctx_;

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
            // TODO: Skip `ObjectiveC*` symbols, since they aren't functions.
            string name;
            switch (sym->getKind()) {
            case SymbolKind::ObjectiveCClass:
                name = ("_OBJC_CLASS_$_" + sym->getName()).str();
                break;
            case SymbolKind::ObjectiveCInstanceVariable:
                name = ("_OBJC_IVAR_$_" + sym->getName()).str();
                break;
            case SymbolKind::ObjectiveCClassEHType:
                name = ("_OBJC_EHTYPE_$_" + sym->getName()).str();
                break;
            case SymbolKind::GlobalSymbol:
                name = sym->getName();
                break;
            default:
                cerr << "Unrecognized symbol type (" << sym->getAnnotatedName() << ")." << endl;
                continue;
            }

            // Save export.
            auto it = exps_.find(name);
            if (it != exps_.end()) {
                it->second.libs.insert(ifile->getInstallName());
            }
            else {
                exps_[name] = export_entry(ifile->getInstallName());
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

        ha.GenerateCode();
    }

    return 0;
}
