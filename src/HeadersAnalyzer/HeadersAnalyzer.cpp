// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Basic/TargetOptions.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Lex/PreprocessorOptions.h>
#include <clang/Parse/ParseAST.h>
#include <clang/AST/Type.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <yaml-cpp/yaml.h>

using namespace clang;
using namespace frontend;
using namespace std;

class HeadersAnalyzer {
public:
    HeadersAnalyzer(CompilerInstance &ci) : ci_(ci) {}
    void Initialize() {}
    void HandleTopLevelDecl(DeclGroupRef d) {}
    void VisitFunction(FunctionDecl &f) {
        // TODO: check that the function is actually exported from the corresponding
        // .dylib file (it's enough to check .tbd file inside the SDK which is simply
        // a YAML)
        //YAML::LoadFile("test.yaml");
        // TODO: maybe use LLVM YAML I/O library instead (http://llvm.org/docs/YamlIO.html)

        // TODO: also check that the function has the same signature in WinObjC headers
        // inside the (NuGet) packages folder

        cout << "if (name == \"" << f.getNameAsString() << "\") {" << endl;

        // We will simply assume arguments are in r0-r3 or on stack for starters.
        // Inspired by /res/IHI0042F_aapcs.pdf (AAPCS), section 5.5 Parameter Passing.

        uint8_t r = 0; // register offset (AAPCS's NCRN)
        uint64_t s = 0; // stack offset (relative AAPCS's NSAA)

        auto fpt = static_cast<const FunctionProtoType *>(f.getFunctionType());
        uint32_t i = 0;
        for (auto &pt : fpt->param_types()) {
            uint64_t bytes = toBytes(ci_.getASTContext().getTypeSize(pt));

            /* #define ARG(i,t) uint8_t a##i[sizeof(t)]; uint32_t *p##i = reinterpret_cast<uint32_t *>(&a##i); uint8_t *c##i = reinterpret_cast<uint8_t *>(&a##i); t *v##i = reinterpret_cast<t *>(&a##i); */

            cout << "ARG(" << to_string(i) << ", " << pt.getAsString() << ")" << endl;

            // Copy data from registers and/or stack into the argument.
            if (r == 4) {
                // We used all the registers, this argument is on the stack.
                // Note that r13 is the stack pointer.
                // TODO: Handle unicorn errors.
                // TODO: Encapsulate this into a macro.
                cout << "uc_mem_read(uc, r13, c" << to_string(i) << " + " << to_string(s) << ", " << to_string(bytes) << ");" << endl;
                s += bytes;
            }
            else {
                assert(bytes > 0 && "non-trivial type expected");
                assert(bytes <= 64 && "we can only handle max. 64-byte-long data for now");

                for (;;) {
                    cout << "p" << to_string(i) << "[" << to_string(r) << "] = r" << to_string(r) << ";" << endl;
                    ++r;

                    if (bytes <= 4) { break; }
                    bytes -= 4;
                }
            }

            ++i;
        }

        // Call the function through a function pointer saved in argument named "address".
        auto pt = ci_.getASTContext().getPointerType(QualType(fpt, 0)); // TODO: How to properly create QualType?
        cout << "reinterpret_cast<" << pt.getAsString() << ">(address)(";
        for (i = 0; i != fpt->getNumParams(); ++i) {
            if (i != 0) { cout << ", "; }
            cout << "*v" << to_string(i);
        }
        cout << ");" << endl;

        // TODO: Handle the return address.
        cout << "return;" << endl;

        cout << "}" << endl;
    }
private:
    CompilerInstance &ci_;

    uint64_t toBytes(uint64_t bits) {
        assert(bits % 8 == 0 && "whole bytes expected");
        return bits / 8;
    }
};

class CustomASTVisitor : public RecursiveASTVisitor<CustomASTVisitor> {
public:
    CustomASTVisitor(HeadersAnalyzer &ha) : ha_(ha) {}
    bool VisitFunctionDecl(FunctionDecl *f) { // TODO: override
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

int main()
{
    // inspired by https://github.com/loarabia/Clang-tutorial/
    // TODO: move this to a separate class

    CompilerInstance ci;
    ci.createDiagnostics();
    ci.getDiagnostics().setIgnoreAllWarnings(true);

    //ci.getHeaderSearchOpts().Sysroot = "C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/";
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/System/Library/Frameworks/", IncludeDirGroup::Angled, /*IsFramework*/ true, /*IgnoreSysRoot*/ false);
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/usr/include/", IncludeDirGroup::Angled, /*IsFramework*/ false, /*IgnoreSysRoot*/ false);
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/clang/lib/Headers/", IncludeDirGroup::Angled, /*IsFramework*/ false, /*IgnoreSysRoot*/ false);
    //ci.getHeaderSearchOpts().ResourceDir = "C:/Users/Jones/Files/Projects/IPASimulator/deps/clang/lib/Headers/";

    auto targetOpts = make_shared<TargetOptions>();
    targetOpts->Triple = "arm-apple-darwin"; // TODO: just a wild guess
    ci.setTarget(TargetInfo::CreateTargetInfo(ci.getDiagnostics(), targetOpts)); // TODO: TargetInfo* should be deleted when not needed anymore

    ci.createFileManager();
    ci.createSourceManager(ci.getFileManager());

    ci.getInvocation().setLangDefaults(ci.getLangOpts(), InputKind::ObjC, ci.getTarget().getTriple(), ci.getPreprocessorOpts());
    ci.getLangOpts().Blocks = 1;

    //ci.getPreprocessorOpts().UsePredefines = false;
    ci.createPreprocessor(TranslationUnitKind::TU_Complete);

    HeadersAnalyzer ha(ci);
    ci.setASTConsumer(make_unique<CustomASTConsumer>(ha));
    ci.createASTContext();
    ha.Initialize();
    ci.createSema(TranslationUnitKind::TU_Complete, nullptr);

    const auto file = ci.getFileManager().getFile("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/System/Library/Frameworks/Foundation.framework/Headers/Foundation.h");
    ci.getSourceManager().setMainFileID(ci.getSourceManager().createFileID(file, SourceLocation(), SrcMgr::C_User));

    ci.getDiagnosticClient().BeginSourceFile(ci.getLangOpts(), &ci.getPreprocessor());
    ParseAST(ci.getSema(), /*PrintStats*/ true, /*SkipFunctionBodies*/ true);
    ci.getDiagnosticClient().EndSourceFile();

    return 0;
}
