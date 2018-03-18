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
#include <llvm/Analysis/OptimizationDiagnosticInfo.h>
#include <llvm/CodeGen/MachineModuleInfo.h>
#include <llvm/CodeGen/GlobalISel/CallLowering.h>
#include <llvm/CodeGen/GlobalISel/MachineIRBuilder.h>
#include <llvm/CodeGen/CallingConvLower.h>
#include <llvm/CodeGen/SelectionDAGISel.h>
#include <llvm/CodeGen/TargetPassConfig.h>
#include <llvm/CodeGen/MachineRegisterInfo.h>
#include <llvm/CodeGen/SelectionDAGISel.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Target/TargetLowering.h>
#include <llvm/Target/TargetSubtargetInfo.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/LegacyPassManager.h>
#include <yaml-cpp/yaml.h>

// Private header files.
#include <llvm/lib/Target/ARM/ARMISelLowering.h>
#include <llvm/lib/CodeGen/SelectionDAG/SelectionDAGBuilder.h>

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
        // TODO: maybe traverse declarations here and clear state of CodeGenerator somehow afterwards
    }
    void VisitFunction(FunctionDecl &f) {
        // dump the function's name and location
        f.printName(llvm::outs());
        llvm::outs() << " ";
        f.getLocation().print(llvm::outs(), f.getASTContext().getSourceManager());
        llvm::outs() << "\n";

        // dump function's type
        auto ft = f.getFunctionType();
        ft->dump(llvm::outs());
        llvm::outs() << "\n";

        // TODO: check that the function is actually exported from the corresponding
        // .dylib file (it's enough to check .tbd file inside the SDK which is simply
        // a YAML)
        //YAML::LoadFile("test.yaml");
        // TODO: maybe use LLVM YAML I/O library instead (http://llvm.org/docs/YamlIO.html)

        // TODO: also check that the function has the same signature in WinObjC headers
        // inside the (NuGet) packages folder

        // We will simply assume arguments are in r0-r3 or on stack for starters.
        // Inspired by /res/IHI0042F_aapcs.pdf (AAPCS), section 5.5 Parameter Passing.

        uint8_t r = 0; // register offset (AAPCS's NCRN)
        uint64_t s = 0; // stack offset (relative AAPCS's NSAA)

        auto fpt = static_cast<const FunctionProtoType *>(ft);
        uint32_t i = 0;
        for (auto &pt : fpt->param_types()) {
            uint64_t bytes = toBytes(ci_.getASTContext().getTypeSize(pt));

            /* #define ARG(i,t) uint8_t a##i[sizeof(t)]; uint32_t *p##i = reinterpret_cast<uint32_t *>(&a##i); uint8_t *c##i = reinterpret_cast<uint8_t *>(&a##i); t *v##i = reinterpret_cast<t *>(&a##i); */

            llvm::outs() << "ARG(" << to_string(i) << ", " << pt.getAsString() << ")\n";

            // Copy data from registers and/or stack into the argument.
            if (r == 4) {
                // We used all the registers, this argument is on the stack.
                // Note that r13 is the stack pointer.
                // TODO: Handle unicorn errors.
                // TODO: Encapsulate this into a macro.
                llvm::outs() << "uc_mem_read(uc, r13, c" << to_string(i) << " + " << to_string(s) << ", " << to_string(bytes) << ");\n";
                s += bytes;
            }
            else {
                assert(bytes > 0 && "non-trivial type expected");
                assert(bytes <= 64 && "we can only handle max. 64-byte-long data for now");

                for (;;) {
                    llvm::outs() << "p" << to_string(i) << "[" << to_string(r) << "] = r" << to_string(r) << ";\n";
                    ++r;

                    if (bytes <= 4) { break; }
                    bytes -= 4;
                }
            }

            ++i;
        }

        // Call the function through a function pointer saved in argument named "address".
        auto pt = ci_.getASTContext().getPointerType(QualType(ft, 0)); // TODO: How to properly create QualType?
        llvm::outs() << "reinterpret_cast<" << pt.getAsString() << ">(address)(";
        for (i = 0; i != fpt->getNumParams(); ++i) {
            if (i != 0) { llvm::outs() << ", "; }
            llvm::outs() << "*v" << to_string(i);
        }
        llvm::outs() << ");";

        // TODO: Handle the return address.

        llvm::outs() << "\n\n";

#if 0
        // generate LLVM IR from the declaration
        auto func = cg_->GetAddrOfGlobal(GlobalDecl(&f), /*isForDefinition*/false);
        auto ffunc = static_cast<llvm::Function *>(func);

        // generate code calling this function using Unicorn's state

        // retrieve target
        string err;
        auto tt = "arm-apple-darwin"; // TODO: obviously, don't hardcode the Triple
        auto t = llvm::TargetRegistry::lookupTarget(tt, err);
        assert(t && "target not found");

        // create target machine
        auto tm = t->createTargetMachine(tt, /*CPU*/ "generic", /*Features*/ "",
            llvm::TargetOptions(), llvm::Optional<llvm::Reloc::Model>());

        // =============================================

        // Create SelectionDAGISel.
        // TODO: Where is this done in LLVM? Is this properly initialized?
        auto armTm = reinterpret_cast<llvm::ARMBaseTargetMachine *>(tm);
        auto fp = llvm::createARMISelDag(*armTm, llvm::CodeGenOpt::Level::None); // ARMPassConfig::addInstSelector <- TargetPassConfig::addCoreISelPasses <- TargetPassConfig::addISelPasses <- addPassesToGenerateCode (LLVMTargetMachine.cpp) <- LLVMTargetMachine::addPassesToEmitFile or LLVMTargetMachine::addPassesToEmitMC
        auto isel = static_cast<llvm::SelectionDAGISel *>(fp);
        // TODO: isel is definitely not properly initialized, it doesn't have MachineFunction!
        // TODO: We should probably run isel.runOnMachineFunction (or at least do the same initialization it does),
        // but first find where it is done in LLVM to "inspire" by it.

        // Create Callee.
        // Inspired by SelectionDAGBuilder::visitInvoke.
        llvm::SDValue callee(isel->SDB->getValue(ffunc));

        // Create Args.
        // Inspired by SelectionDAGBuilder::LowerCallTo.
        llvm::TargetLowering::ArgListTy args;
        args.reserve(ffunc->arg_size());
        for (auto &arg : ffunc->args()) {
            // Skip empty values.
            if (arg.getType()->isEmptyTy()) { continue; }

            llvm::TargetLowering::ArgListEntry entry;
            entry.Node = isel->SDB->getValue(&arg);
            entry.Ty = arg.getType();
            args.push_back(entry);
        }

        // Create CallLoweringInfo.
        // Inspired by SelectionDAGBuilder::LowerCallTo.
        llvm::TargetLowering::CallLoweringInfo cli(*isel->CurDAG);
        cli.setDebugLoc(isel->SDB->getCurSDLoc())
            .setChain(isel->SDB->getRoot())
            .setCallee(ffunc->getCallingConv(), ffunc->getReturnType(), callee, move(args))
            .setTailCall(false) // TODO: Support tail calls (?)
            .setConvergent(ffunc->isConvergent());

        // Lower call.
        // Inspired by SelectionDAGBuilder::lowerInvokable.
        auto result = isel->TLI->LowerCallTo(cli);

        // =============================================
#endif
    }
private:
    llvm::LLVMContext ctx_;
    CompilerInstance &ci_;
    CodeGenerator *cg_;

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
