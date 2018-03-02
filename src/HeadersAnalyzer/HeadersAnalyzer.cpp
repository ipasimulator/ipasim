// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include <iostream>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Basic/TargetOptions.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Lex/PreprocessorOptions.h>
#include <clang/Parse/ParseAST.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Target/TargetLowering.h>
#include <llvm/IR/LLVMContext.h>
#include <yaml-cpp/yaml.h>

using namespace clang;
using namespace frontend;
using namespace std;

class HeadersAnalyzer {
public:
    HeadersAnalyzer(CompilerInstance &ci) : ci_(ci) {
        llvm::InitializeAllTargetInfos();
        llvm::InitializeAllTargets();
        llvm::InitializeAllTargetMCs();

        cg_ = CreateLLVMCodeGen(ci_.getDiagnostics(), "", ci_.getHeaderSearchOpts(),
            ci_.getPreprocessorOpts(), ci_.getCodeGenOpts(), ctx_); // TODO: this pointer must be deleted!
    }
    void Initialize() {
        cg_->Initialize(ci_.getASTContext()); // TODO: just a wild guess, is it necessary?
    }
    void HandleTopLevelDecl(DeclGroupRef d) {
        cg_->HandleTopLevelDecl(d);
    }
    void VisitFunction(FunctionDecl &f) {
        // dump the function's name and location
        f.printName(llvm::outs());
        llvm::outs() << " ";
        f.getLocation().print(llvm::outs(), f.getASTContext().getSourceManager());
        llvm::outs() << "\n";

        // TODO: check that the function is actually exported from the corresponding
        // .dylib file (it's enough to check .tbd file inside the SDK which is simply
        // a YAML)
        //YAML::LoadFile("test.yaml");

        // TODO: also check that the function has the same signature in WinObjC headers
        // inside the (NuGet) packages folder

        // generate LLVM IR from the declaration
        auto func = cg_->GetAddrOfGlobal(GlobalDecl(&f), /*isForDefinition*/false);
        auto ffunc = static_cast<llvm::Function *>(func);

        // generate code calling this function using Unicorn's state
        string err;
        auto tt = "arm-apple-darwin"; // TODO: obviously, don't hardcode the Triple
        auto t = llvm::TargetRegistry::lookupTarget(tt, err);
        assert(t && "target not found");
        auto tm = t->createTargetMachine(tt, /*CPU*/ "generic", /*Features*/ "",
            llvm::TargetOptions(), llvm::Optional<llvm::Reloc::Model>());
        llvm::TargetLowering tl(*tm);
        llvm::SelectionDAG dag(*tm, llvm::CodeGenOpt::Level::None); // TODO: this does not seem properly initialized, should we rather retrieve it from somewhere?
        //dag.init()
        llvm::TargetLowering::CallLoweringInfo cli(dag);
        auto pair = tl.LowerCallTo(cli);
        cout << "success" << endl;
    }
private:
    llvm::LLVMContext ctx_;
    CompilerInstance &ci_;
    CodeGenerator *cg_;
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
