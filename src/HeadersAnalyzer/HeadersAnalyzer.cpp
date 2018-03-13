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
#include <llvm/Analysis/OptimizationDiagnosticInfo.h>
#include <llvm/CodeGen/MachineModuleInfo.h>
#include <llvm/CodeGen/GlobalISel/CallLowering.h>
#include <llvm/CodeGen/GlobalISel/MachineIRBuilder.h>
#include <llvm/CodeGen/CallingConvLower.h>
#include <llvm/CodeGen/SelectionDAGISel.h>
#include <llvm/CodeGen/TargetPassConfig.h>
#include <llvm/CodeGen/MachineRegisterInfo.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Target/TargetLowering.h>
#include <llvm/Target/TargetSubtargetInfo.h>
#include <llvm/Transforms/IPO/PassManagerBuilder.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/PassManager.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/lib/Target/ARM/ARMISelLowering.h>
#include <yaml-cpp/yaml.h>

using namespace clang;
using namespace frontend;
using namespace std;

// HACK: this should be included from llvm/Target/ARM/ARM.h instead
namespace llvm {
    class ARMBaseTargetMachine;
    FunctionPass *createARMISelDag(ARMBaseTargetMachine &TM, CodeGenOpt::Level OptLevel);
}

// inspired by OutgoingValueHandler from ARMCallLowering.cpp
// HACK: there is a lot of code copied right now
class CustomValueHandler : public llvm::CallLowering::ValueHandler {
public:
    CustomValueHandler(llvm::MachineIRBuilder &mirb, llvm::MachineRegisterInfo &mri,
        llvm::CCAssignFn *assignFn) : ValueHandler(mirb, mri, assignFn), StackSize(0) {}

    unsigned getStackAddress(uint64_t Size, int64_t Offset, llvm::MachinePointerInfo &MPO) override {
        assert((Size == 1 || Size == 2 || Size == 4 || Size == 8) && "Unsupported size");

        llvm::LLT p0 = llvm::LLT::pointer(0, 32);
        llvm::LLT s32 = llvm::LLT::scalar(32);
        unsigned SPReg = MRI.createGenericVirtualRegister(p0);
        //MIRBuilder.buildCopy(SPReg, ARM::SP);

        unsigned OffsetReg = MRI.createGenericVirtualRegister(s32);
        //MIRBuilder.buildConstant(OffsetReg, Offset);

        unsigned AddrReg = MRI.createGenericVirtualRegister(p0);
        //MIRBuilder.buildGEP(AddrReg, SPReg, OffsetReg);

        MPO = llvm::MachinePointerInfo::getStack(MIRBuilder.getMF(), Offset);
        return AddrReg;
    }

    void assignValueToReg(unsigned ValVReg, unsigned PhysReg, llvm::CCValAssign &VA) override {
        assert(VA.isRegLoc() && "Value shouldn't be assigned to reg");
        assert(VA.getLocReg() == PhysReg && "Assigning to the wrong reg?");

        assert(VA.getValVT().getSizeInBits() <= 64 && "Unsupported value size");
        assert(VA.getLocVT().getSizeInBits() <= 64 && "Unsupported location size");

        unsigned ExtReg = extendRegister(ValVReg, VA);
        MIRBuilder.buildCopy(PhysReg, ExtReg);
        //MIB.addUse(PhysReg, RegState::Implicit);
    }

    void assignValueToAddress(unsigned ValVReg, unsigned Addr, uint64_t Size,
        llvm::MachinePointerInfo &MPO, llvm::CCValAssign &VA) override {
        assert((Size == 1 || Size == 2 || Size == 4 || Size == 8) && "Unsupported size");

        unsigned ExtReg = extendRegister(ValVReg, VA);
        auto MMO = MIRBuilder.getMF().getMachineMemOperand(
            MPO, llvm::MachineMemOperand::MOStore, VA.getLocVT().getStoreSize(),
            /* Alignment */ 0);
        MIRBuilder.buildStore(ExtReg, Addr, *MMO);
    }

    unsigned assignCustomValue(const llvm::CallLowering::ArgInfo &Arg,
        ArrayRef<llvm::CCValAssign> VAs) override {
        llvm::CCValAssign VA = VAs[0];
        assert(VA.needsCustom() && "Value doesn't need custom handling");
        assert(VA.getValVT() == llvm::MVT::f64 && "Unsupported type");

        llvm::CCValAssign NextVA = VAs[1];
        assert(NextVA.needsCustom() && "Value doesn't need custom handling");
        assert(NextVA.getValVT() == llvm::MVT::f64 && "Unsupported type");

        assert(VA.getValNo() == NextVA.getValNo() &&
            "Values belong to different arguments");

        assert(VA.isRegLoc() && "Value should be in reg");
        assert(NextVA.isRegLoc() && "Value should be in reg");

        unsigned NewRegs[] = { MRI.createGenericVirtualRegister(llvm::LLT::scalar(32)),
            MRI.createGenericVirtualRegister(llvm::LLT::scalar(32)) };
        MIRBuilder.buildUnmerge(NewRegs, Arg.Reg);

        //bool IsLittle = MIRBuilder.getMF().getSubtarget<ARMSubtarget>().isLittle();
        //if (!IsLittle)
        //    std::swap(NewRegs[0], NewRegs[1]);

        assignValueToReg(NewRegs[0], VA.getLocReg(), VA);
        assignValueToReg(NewRegs[1], NextVA.getLocReg(), NextVA);

        return 1;
    }

    bool assignArg(unsigned ValNo, llvm::MVT ValVT, llvm::MVT LocVT,
        llvm::CCValAssign::LocInfo LocInfo,
        const llvm::CallLowering::ArgInfo &Info, llvm::CCState &State) override {
        if (AssignFn(ValNo, ValVT, LocVT, LocInfo, Info.Flags, State))
            return true;

        StackSize =
            std::max(StackSize, static_cast<uint64_t>(State.getNextStackOffset()));
        return false;
    }

    uint64_t StackSize;
};

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

        // dump funtion's type
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

#if 0
        // inspired by ARMCallLowering::lowerCall
        auto st = tm->getSubtargetImpl(*ffunc);
        auto tl = static_cast<const llvm::ARMTargetLowering *>(st->getTargetLowering());
        llvm::SmallVector<llvm::CallLowering::ArgInfo, 8> args;
        auto assignFn = tl->CCAssignFnForCall(ffunc->getCallingConv(), ffunc->isVarArg());
        llvm::MachineIRBuilder mirb;
        llvm::MachineModuleInfo mmi(tm);
        auto &mf = mmi.getOrCreateMachineFunction(*ffunc);
        CustomValueHandler handler(mirb, mf.getRegInfo(), assignFn);
        // TODO: I'm stuck here
#endif

#if 0
        // inspired by CallLowering::handleAssignments
        auto st = tm->getSubtargetImpl(*ffunc);
        auto tl = static_cast<const llvm::ARMTargetLowering *>(st->getTargetLowering());
        auto assignFn = tl->CCAssignFnForCall(ffunc->getCallingConv(), ffunc->isVarArg());
        llvm::MachineModuleInfo mmi(tm);
        auto &mf = mmi.getOrCreateMachineFunction(*ffunc);
        SmallVector<llvm::CCValAssign, 16> argLocs;
        llvm::CCState cc(ffunc->getCallingConv(), ffunc->isVarArg(), mf, argLocs, ffunc->getContext());
        unsigned i = 0;
        for (auto &arg : ffunc->args()) {
            // TODO: do what the ARMCallLowering::splitToValueTypes function does
            // TODO: isSupportedType inside ARMCallLowering returns false for i64,
            // because it should be already lowered
            // (see https://github.com/llvm-mirror/llvm/blob/f0eff632cbd02ce021942cd412a011a6fff8d9bd/lib/Target/ARM/ARMISelLowering.cpp#L3769)
            auto vt = llvm::MVT::getVT(arg.getType());
            bool result = assignFn(i, vt, vt, llvm::CCValAssign::LocInfo::Full, llvm::ISD::ArgFlagsTy(), cc);
            cout << result << endl; // true means failure
            ++i;
        }
#endif

#if 0
        // create SelectionDAGISel
        auto armTm = reinterpret_cast<llvm::ARMBaseTargetMachine *>(tm);
        auto fp = llvm::createARMISelDag(*armTm, llvm::CodeGenOpt::Level::None);
        auto dag = static_cast<llvm::SelectionDAGISel *>(fp);
#endif

#if 0
        // register with PassManager
        llvm::PassManagerBuilder pmb;
        llvm::legacy::FunctionPassManager pm(ffunc->getParent());
        auto llvmTm = static_cast<llvm::LLVMTargetMachine *>(tm);
        llvmTm->adjustPassManager(pmb);
        pmb.populateFunctionPassManager(pm);
        llvm::MCContext *mcc = nullptr;
        llvm::SmallVector<char, 4096> buffer;
        llvm::raw_svector_ostream os(buffer);
        bool result = llvmTm->addPassesToEmitMC(pm, mcc, os);
        //auto config = llvmTm->createPassConfig(pm);
        //bool result = config->addInstSelector();
        assert(result && "addPassesToEmitMC shouldn't fail"); // TODO: returning true probably means failure

        // TODO: retrieve ARMISelDag pass from the PassManager and runOnMachineFunction it
#endif

#if 0
        // lower func
        pm.doInitialization();
        pm.run(*ffunc);
#endif

#if 0
        // create machine function
        auto &mmi = fp->getAnalysis<llvm::MachineModuleInfo>();
        auto &mf = mmi.getOrCreateMachineFunction(*ffunc);

        // lower function
        result = dag->runOnMachineFunction(mf);
        assert(result && "runOnMachineFunction shouldn't fail");
#endif

#if 0
        // get call lowering
        auto st = tm->getSubtargetImpl(*ffunc);
        auto cl = st->getCallLowering();
#endif

        // TODO: why this failed? It seems OK.
        // Get inspiration in ARMTargetLowering::LowerFormalArguments.
        // (For example, use CCInfo.AnalyzeFormalArguments.)
#if 0
        // lower call
        llvm::TargetLowering tl(*tm);
        llvm::SelectionDAG dag(*tm, llvm::CodeGenOpt::Level::None); // TODO: this does not seem properly initialized, should we rather retrieve it from somewhere?
        llvm::OptimizationRemarkEmitter ore(ffunc);
        dag.init(mf, ore);
        llvm::TargetLowering::CallLoweringInfo cli(dag);
        //cli.setCallee(ffunc->getCallingConv(), ffunc->getReturnType(), /**/SDValue());
        auto pair = tl.LowerCallTo(cli); // TODO: maybe use FastISel.LowerCallTo, so that we don't have to create SelectionDAG...
#endif

#if 0
        // Inspired by ARMTargetLowering::LowerFormalArguments.
        // ====================================================

        // Create MachineFunction.
        // TODO: Is this the proper way to do it?
        llvm::MachineModuleInfo mmi(tm);
        auto &mf = mmi.getOrCreateMachineFunction(*ffunc);

        // Create CCState.
        SmallVector<llvm::CCValAssign, 16> argLocs;
        llvm::CCState cc(ffunc->getCallingConv(), ffunc->isVarArg(), mf, argLocs, ffunc->getContext());

        // Retrieve CCAssignFn.
        auto st = tm->getSubtargetImpl(*ffunc);
        auto tl = static_cast<const llvm::ARMTargetLowering *>(st->getTargetLowering());
        auto assignFn = tl->CCAssignFnForCall(ffunc->getCallingConv(), ffunc->isVarArg());

        // Analyze formal arguments.
        SmallVector<llvm::ISD::InputArg, 16> ins;
        cc.AnalyzeFormalArguments(ins, assignFn);
        // TODO: This doesn't work, we need to fill ins somehow.

        // ====================================================

        // TODO: try to use https://llvm.org/docs/GlobalISel.html
        // (instead of SelectionDAG and FastISel - https://llvm.org/docs/CodeGenerator.html).
        // OK, that just emits IR, so it's not so useful.
#endif

#if 0
        SmallVector<llvm::CCValAssign, 16> argLocs;
        llvm::CCState cc(ffunc->getCallingConv(), ffunc->isVarArg(), mf, argLocs, ffunc->getContext());

        SmallVector<llvm::ISD::InputArg, 16> ins;
        ins.push_back(llvm::ISD::InputArg()); // TODO: how to create InputArg?
#endif

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
