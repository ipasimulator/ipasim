// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include "ClangHelper.hpp"
#include "Config.hpp"
#include "HAContext.hpp"
#include "LLVMHelper.hpp"

#include <Plugins/ObjectFile/PECOFF/ObjectFilePECOFF.h>
#include <Plugins/SymbolFile/PDB/PDBASTParser.h>
#include <Plugins/SymbolFile/PDB/SymbolFilePDB.h>
#include <lldb/API/SBDebugger.h>
#include <lldb/Core/Debugger.h>
#include <lldb/Core/Module.h>
#include <lldb/Symbol/ClangASTContext.h>
#include <lldb/Symbol/ClangUtil.h>
#include <lldb/Symbol/SymbolVendor.h>
#include <lldb/Symbol/Type.h>
#include <lldb/Utility/DataBufferHeap.h>

#include <tapi/Core/FileManager.h>
#include <tapi/Core/InterfaceFile.h>
#include <tapi/Core/InterfaceFileManager.h>

#include <CodeGen/CodeGenModule.h>
#include <clang/AST/ASTContext.h>
#include <clang/AST/GlobalDecl.h>
#include <clang/AST/Mangle.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/AST/Type.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Basic/TargetOptions.h>
#include <clang/CodeGen/CodeGenABITypes.h>
#include <clang/CodeGen/CodeGenAction.h>
#include <clang/CodeGen/ModuleBuilder.h>
#include <clang/Driver/Compilation.h>
#include <clang/Driver/Driver.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/Utils.h>
#include <clang/Lex/PreprocessorOptions.h>
#include <clang/Parse/ParseAST.h>

#include <llvm/DebugInfo/PDB/IPDBSession.h>
#include <llvm/DebugInfo/PDB/PDB.h>
#include <llvm/DebugInfo/PDB/PDBSymbolExe.h>
#include <llvm/DebugInfo/PDB/PDBSymbolFunc.h>
#include <llvm/Demangle/Demangle.h>
#include <llvm/IR/DebugInfo.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/IntrinsicInst.h>
#include <llvm/IR/Intrinsics.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/LegacyPassManager.h>
#include <llvm/IR/Mangler.h>
#include <llvm/IR/Module.h>
#include <llvm/IR/ValueHandle.h>
#include <llvm/IR/Verifier.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/ErrorHandling.h>
#include <llvm/Support/TargetRegistry.h>
#include <llvm/Support/TargetSelect.h>
#include <llvm/Support/raw_os_ostream.h>
#include <llvm/Target/TargetMachine.h>
#include <llvm/Transforms/Utils/FunctionComparator.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <vector>

using namespace clang;
using namespace frontend;
using namespace std;
using namespace filesystem;
using namespace tapi::internal;

enum class export_status { NotFound = 0, Found, Overloaded, Generated };

struct export_entry {
  export_entry() : status(export_status::NotFound), decl(nullptr) {}
  export_entry(string firstLib)
      : status(export_status::NotFound), decl(nullptr) {
    libs.insert(move(firstLib));
  }

  set<string> libs;
  export_status status;
  const FunctionDecl *decl;
};

// Key is symbol name.
using export_list = map<string, export_entry>;

class tbd_handler {
public:
  tbd_handler(export_list &exps)
      : exps_(exps), fm_(FileSystemOptions()), ifm_(fm_) {}
  void handle_tbd_file(const string &path) {
    // Check file.
    auto fileOrError = ifm_.readFile(path);
    if (!fileOrError) {
      cerr << "Error: " << llvm::toString(fileOrError.takeError()) << " ("
           << path << ")." << endl;
      return;
    }
    auto file = *fileOrError;
    if (!file->getArchitectures().contains(Architecture::armv7)) {
      cerr << "TBD file does not contain architecture ARMv7 (" << path << ")."
           << endl;
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
        cerr << "Unrecognized symbol type (" << sym->getAnnotatedName() << ")."
             << endl;
        continue;
      }

      // Save export.
      auto it = exps_.find(name);
      if (it != exps_.end()) {
        it->second.libs.insert(ifile->getInstallName());
      } else {
        exps_[name] = export_entry(ifile->getInstallName());
      }
    }
  }

private:
  export_list &exps_;
  tapi::internal::FileManager fm_;
  InterfaceFileManager ifm_;
};

class ObjectFileUnimplemented : public lldb_private::ObjectFile {
public:
  ObjectFileUnimplemented(const lldb::ModuleSP &Module,
                          const lldb::DataBufferSP &Buffer)
      : ObjectFile(Module, nullptr, 0, 0, Buffer, 0) {}

#define unimplemented throw 1
  void Dump(lldb_private::Stream *S) override { unimplemented; }
  uint32_t GetAddressByteSize() const override { unimplemented; }
  uint32_t GetDependentModules(lldb_private::FileSpecList &file_list) override {
    unimplemented;
  }
  bool IsExecutable() const override { unimplemented; }
  bool GetArchitecture(lldb_private::ArchSpec &arch) override { unimplemented; }
  void
  CreateSections(lldb_private::SectionList &unified_section_list) override {
    unimplemented;
  }
  lldb_private::Symtab *GetSymtab() override { unimplemented; }
  bool IsStripped() override { unimplemented; }
  bool GetUUID(lldb_private::UUID *uuid) override { unimplemented; }
  lldb::ByteOrder GetByteOrder() const override { unimplemented; }
  bool ParseHeader() override { unimplemented; }
  Type CalculateType() override { unimplemented; }
  Strata CalculateStrata() override { unimplemented; }
  lldb_private::ConstString GetPluginName() override { unimplemented; }
  uint32_t GetPluginVersion() override { unimplemented; }
#undef unimplemented
};
class ObjectFileDummy : public ObjectFileUnimplemented {
public:
  ObjectFileDummy(const lldb::ModuleSP &Module,
                  const lldb::DataBufferSP &Buffer)
      : ObjectFileUnimplemented(Module, Buffer) {}
};

class TypeComparer {
public:
  // Note that if we got `PDBAstParser` from `Module` rather then created it,
  // `CreateLLDBTypeFromPDBType` wouldn't work - see branch `cg_got_clang_ctx`.
  TypeComparer(CodeGen::CodeGenModule &CGM, llvm::Module *Module,
               lldb_private::SymbolFile *SymbolFile)
      : CGM(CGM), Module(Module), ClangCtx(), Parser(ClangCtx) {
    ClangCtx.SetSymbolFile(SymbolFile);
  }

  llvm::Type *getLLVMType(const llvm::pdb::PDBSymbol &Symbol) {
    using namespace lldb;
    using namespace lldb_private;

    TypeSP LLDBType = Parser.CreateLLDBTypeFromPDBType(Symbol);
    QualType CanonType =
        ClangUtil::GetCanonicalQualType(LLDBType->GetFullCompilerType());
    return convertTypeForMemory(CGM, CanonType);
  }
  bool areEqual(const llvm::Type *Type, const llvm::pdb::PDBSymbol &Symbol) {
    return Type == getLLVMType(Symbol);
  }
  bool areEquivalent(llvm::FunctionType *Func,
                     const llvm::pdb::PDBSymbolFunc &SymbolFunc) {
    auto *Func2 = static_cast<llvm::FunctionType *>(getLLVMType(SymbolFunc));
    return FunctionComparer::compareTypes(Module, Func, Func2) == 0;
  }

private:
  CodeGen::CodeGenModule &CGM;
  llvm::Module *Module;
  lldb_private::ClangASTContext ClangCtx;
  PDBASTParser Parser;

  // Just to get access to protected function `cmpTypes`.
  class FunctionComparer : llvm::FunctionComparator {
  public:
    static int compareTypes(llvm::Module *Module, llvm::FunctionType *FTy1,
                            llvm::FunctionType *FTy2) {
      return FunctionComparer(Module, FTy1).cmpTypes(FTy1, FTy2);
    }

  private:
    FunctionComparer(llvm::Module *Module, llvm::FunctionType *FTy)
        : FunctionComparator(
              llvm::Function::Create(FTy, llvm::GlobalValue::ExternalLinkage,
                                     "", Module),
              nullptr, nullptr) {}
  };
};

// This is an inverse of `CGObjCCommonMac::GetNameForMethod`.
// TODO: Find out whether there aren't any Objective-C method name parsers
// somewhere in the LLVM ecosystem already.
static auto findClassMethod(const ClassExportList &CEL, const string &Name) {
  if (Name[0] != '+' && Name[0] != '-')
    return CEL.end();
  if (Name[1] != '[')
    return CEL.end();

  // Find the first space.
  size_t SpaceIdx = Name.find(' ', 2);
  if (SpaceIdx == string::npos)
    return CEL.end();

  // From `[` to the first space is a class name.
  string ClassName = Name.substr(2, SpaceIdx - 2);

  // On Mach systems, names are mangled with leading underscore.
  return CEL.find('_' + ClassName);
}

class SBDebuggerGuard {
public:
  SBDebuggerGuard() { lldb::SBDebugger::Initialize(); }
  ~SBDebuggerGuard() { lldb::SBDebugger::Terminate(); }
};

class HeadersAnalyzer {
public:
  void parseAppleHeaders() {
    LLVMHelper LLVM(LLVMInit);
    ClangHelper Clang(LLVM);
    Clang.Args.loadConfigFile("./src/HeadersAnalyzer/analyze_ios_headers.cfg");
    Clang.initFromInvocation();

    // Include all declarations in the result. See [emit-all-decls].
    // TODO: Maybe filter them (include only those exported from iOS Dylibs).
    Clang.CI.getLangOpts().EmitAllDecls = true;

    // Compile to LLVM IR.
    Clang.executeAction<EmitLLVMOnlyAction>();

    // Analyze functions.
    for (const llvm::Function &Func : *LLVM.getModule()) {
      string Name = LLVM.mangleName(Func);
      if (!HAC.isInteresting(Name))
        continue;
    }
  }

private:
  HAContext HAC;
  LLVMInitializer LLVMInit;
};

int main() {
  ExportList iOSExps;
  auto addExp = [&](string Name) {
    return &*iOSExps.insert(ExportEntry(Name)).first;
  };
  vector<Dylib> iOSLibs = {
      {"/usr/lib/libobjc.A.dylib",
       {addExp("_sel_registerName"), addExp("_object_setIvar")}}};
  ClassExportList iOSClasses = {{"_NSObject", 0}};
  vector<DLLGroup> DLLGroups = {
      {"./src/objc/Debug/", {DLLEntry("libobjc.A.dll")}}};

  // Parse iOS headers.
  // TODO: This is so up here just for testing. In production, it should be
  // lower.
  {
    // Parse the response file.
    llvm::BumpPtrAllocator A;
    llvm::StringSaver Saver(A);
    // First argument should be an executable name.
    llvm::SmallVector<const char *, 256> Argv = {"clang.exe"};
    if (!llvm::cl::readConfigFile(
            "./src/HeadersAnalyzer/analyze_ios_headers.cfg", Saver, Argv)) {
      cerr << "Error: couldn't parse the response file." << endl;
      return 1;
    }

    // Initialize LLVM for code generation.
    llvm::InitializeAllTargetInfos();
    llvm::InitializeAllTargets();
    llvm::InitializeAllTargetMCs();
    llvm::InitializeAllAsmPrinters();

    // Create `CompilerInstance` of Clang.
    CompilerInstance CI;
    // TODO: No diagnostics options set at the beginning (like ignore unknown
    // arguments, etc.). How should that be done?
    CI.createDiagnostics();
    CI.setInvocation(
        createInvocationFromCommandLine(Argv, &CI.getDiagnostics()));

    // Include all declarations in the result.
    // TODO: Maybe filter them (include only those in `Exps`).
    CI.getLangOpts().EmitAllDecls = true;

    // Compile to LLVM IR.
    llvm::LLVMContext Ctx;
    EmitLLVMOnlyAction Act(&Ctx);
    if (!CI.ExecuteAction(Act))
      return 1;
    auto Module = Act.takeModule();

    // Find exported functions.
    for (const llvm::Function &Func : *Module) {
      // Mangle the name to compare it with iOS exports.
      llvm::SmallString<16> Name;
      llvm::Mangler().getNameWithPrefix(Name, &Func,
                                        /* CannotUsePrivateLabel */ false);

      // Filter uninteresting functions.
      string NameStr(Name.str().str());
      auto Exp = iOSExps.find(NameStr);
      if (Exp == iOSExps.end()) {
        // If not found among exported functions, try if it isn't an Objective-C
        // function.
        auto Class = findClassMethod(iOSClasses, NameStr);
        if (Class != iOSClasses.end()) {
          Exp = iOSExps.insert(ExportEntry(NameStr)).first;
          Exp->ObjCMethod = true;
          iOSLibs[Class->second].Exports.push_back(&*Exp);
        } else {
          if constexpr (WarnUninterestingFunctions & LibType::Dylib) {
            cerr << "Warning: found uninteresting function in Dylib ("
                 << NameStr << "). Isn't that interesting?\n";
          }
          continue;
        }
      }

      // Update status accordingly.
      switch (Exp->Status) {
      case ExportStatus::Found:
        Exp->Status = ExportStatus::Overloaded;
        cerr << "Error: function overloaded (" << NameStr << ").\n";
        continue;
      case ExportStatus::Overloaded:
        continue;
      case ExportStatus::NotFound:
        Exp->Status = ExportStatus::Found;
        break;
      default:
        llvm_unreachable("Unexpected status of `ExportEntry`.");
      }

      // Save the function's signature.
      Exp->Type = Func.getFunctionType();
    }

    if constexpr (ErrorUnimplementedFunctions & LibType::Dylib) {
      for (auto &Exp : iOSExps) {
        if (Exp.Status == ExportStatus::NotFound) {
          cerr << "Error: function found in TBD files wasn't found in any "
                  "Dylib ("
               << Exp.Name << ").\n";
        }
      }
    }

    // Create `CodeGenModule`.
    CI.createASTContext();
    CodeGen::CodeGenModule CGM(CI.getASTContext(), CI.getHeaderSearchOpts(),
                               CI.getPreprocessorOpts(), CI.getCodeGenOpts(),
                               *Module, CI.getDiagnostics());

    // Initialize LLDB.
    using namespace lldb;
    using namespace lldb_private;
    using namespace llvm::pdb;
    SBDebuggerGuard DebuggerGuard;
    DebuggerSP Debugger = Debugger::CreateInstance();

    // Load DLLs and PDBs.
    for (DLLGroup &DLLGroup : DLLGroups) {
      for (DLLEntry &DLL : DLLGroup.DLLs) {
        path DLLPath(DLLGroup.Dir / DLL.Name);
        path PDBPath(DLLPath);
        PDBPath.replace_extension(".pdb");

        // Load PDB into LLDB. This is a hack, actually, because no simple way
        // of loading the PDB worked for us. We do this simply because we use
        // some LLDB functions in our `TypeComparer` and they require some
        // initialized LLDB structures (like `SymbolFile`). Otherwise, we
        // wouldn't need LLDB at all, since we work directly with `IPDBSession`
        // which is a LLVM object that can work without LLDB. Although, for some
        // reason, the DIA SDK is not registered properly when we don't use
        // `Debugger::Initialize`, so this would also have to be solved before
        // removing LLDB from our dependencies completely.
        ModuleSpec ModuleSpec(FileSpec(DLLPath.string().c_str(),
                                       /* resolve_path */ true));
        ModuleSpec.GetSymbolFileSpec().SetFile(PDBPath.string().c_str(),
                                               /* resolve_path */ true);
        ModuleSP LLDBModule =
            Debugger->GetSelectedOrDummyTarget()->GetSharedModule(ModuleSpec);
        DataBufferSP Buffer(new DataBufferHeap);
        ObjectFileDummy Obj(LLDBModule, Buffer);
        SymbolFile *SymbolFile = SymbolFilePDB::CreateInstance(&Obj);
        SymbolFile->CalculateAbilities(); // Initialization, actually.
        SymbolFilePDB *PDB = static_cast<SymbolFilePDB *>(SymbolFile);
        // TODO: Get rid of `.get()`.
        TypeComparer TC(CGM, Module.get(), SymbolFile);

        // Process functions.
        auto SymbolExe = PDB->GetPDBSession().getGlobalScope();
        auto EnumSymbols = SymbolExe->findAllChildren(PDB_SymType::Function);
        uint32_t SymbolCount = EnumSymbols->getChildCount();
        for (uint32_t I = 0; I != SymbolCount; ++I) {
          auto Symbol = EnumSymbols->getChildAtIndex(I);
          auto Func = static_cast<PDBSymbolFunc *>(Symbol.get());

          // Get function's name, mangled if possible.
          string Name = Func->getUndecoratedName();
          if (Name.empty()) {
            Name = Func->getName();
            assert(!Name.empty() && "A function has no name.");
          }

          // Find the corresponding iOS export.
          auto Exp = iOSExps.find(Name);
          if (Exp == iOSExps.end() || Exp->Status != ExportStatus::Found) {
            if constexpr (WarnUninterestingFunctions & LibType::DLL) {
              cerr << "Warning: found uninteresting function in DLL (" << Name
                   << "). Isn't that interesting?\n";
            }
            continue;
          }
          Exp->Status = ExportStatus::FoundInDLL;
          Exp->RVA = Func->getRelativeVirtualAddress();
          DLL.Exports.push_back(&*Exp);
          Exp->DLLGroup = &DLLGroup;
          Exp->DLL = &DLL;

          // Save function that will serve as a reference for computing
          // addresses of Objective-C methods.
          if (!DLL.ReferenceFunc && !Exp->ObjCMethod) {
            DLL.ReferenceFunc = &*Exp;
          }

          // Verify that the function has the same signature as the iOS one.
          if (!TC.areEquivalent(Exp->Type, *Func)) {
            cerr << "Error: functions' signatures are not equivalent ("
                 << Exp->Name << ").\n";
          }
        }
      }
    }

    // Create output directories.
    path OutputDir("./src/HeadersAnalyzer/Debug/");
    {
      error_code E;
      if (!create_directories(OutputDir, E) && E) {
        cerr << "Fatal error while creating output directory: " << E.message()
             << '\n';
        return 1;
      }
    }
    path WrappersDir("./out/Wrappers/");
    {
      error_code E;
      if (!create_directories(WrappersDir, E) && E) {
        cerr << "Fatal error while creating wrappers directory: " << E.message()
             << '\n';
        return 1;
      }
    }
    path DylibsDir("./out/Dylibs/");
    {
      error_code E;
      if (!create_directories(DylibsDir, E) && E) {
        cerr << "Fatal error while creating Dylibs directory: " << E.message()
             << '\n';
        return 1;
      }
    }

    // DLL function wrappers have all type `(void *) -> void`.
    llvm::Type *VPTy = llvm::Type::getInt8PtrTy(Ctx);
    llvm::FunctionType *WrapperTy =
        llvm::FunctionType::get(llvm::Type::getVoidTy(Ctx), {VPTy},
                                /* isVarArg */ false);

    // Generate iOS libraries.
    size_t LibIdx = 0;
    for (const Dylib &Lib : iOSLibs) {
      string LibNo = to_string(LibIdx++);

      // Prepare for IR generation.
      llvm::IRBuilder<> Builder(Ctx);
      llvm::Module LibModule(LibNo, Ctx);
      LibModule.setSourceFileName(Lib.Name);
      LibModule.setTargetTriple(Module->getTargetTriple());
      LibModule.setDataLayout(Module->getDataLayout());

      // Generate function wrappers.
      // TODO: Shouldn't we use aligned instructions?
      for (const ExportEntry *Exp : Lib.Exports) {

        // Ignore functions that haven't been found in any DLL.
        if (Exp->Status != ExportStatus::FoundInDLL) {
          if constexpr (ErrorUnimplementedFunctions & LibType::DLL) {
            if (Exp->Status == ExportStatus::Found) {
              cerr << "Error: function found in Dylib wasn't found in any DLL ("
                   << Exp->Name << ").\n";
            }
          }
          continue;
        }

        // Declaration. Note that we add prefix `\01`, so that the name doesn't
        // get mangled since it already is. LLVM will remove this prefix before
        // emitting object code for the function.
        llvm::Function *Func =
            llvm::Function::Create(Exp->Type, llvm::Function::ExternalLinkage,
                                   '\01' + Exp->Name, &LibModule);

        // DLL wrapper declaration.
        llvm::Function *Wrapper = llvm::Function::Create(
            WrapperTy, llvm::Function::ExternalLinkage,
            "\01$__ipaSim_wrapper_" + to_string(Exp->RVA), &LibModule);

        // TODO: Handle variadic functions.

        // Map parameter types to their pointers.
        vector<llvm::Type *> ParamPointers;
        ParamPointers.reserve(Exp->Type->getNumParams());
        for (llvm::Type *Ty : Exp->Type->params()) {
          ParamPointers.push_back(Ty->getPointerTo());
        }

        // Create a structure that we will use to store the function's arguments
        // and return value. It's actually a union of a structure and of the
        // return value where the structure in the union contains addresses of
        // the arguments.
        llvm::StructType *Struct =
            llvm::StructType::create(ParamPointers, "struct");

        // In LLVM IR, union is simply a struct containing the largest element.
        llvm::Type *RetTy = Exp->Type->getReturnType();
        llvm::Type *ContainedTy;
        if (RetTy->isVoidTy() ||
            Struct->getScalarSizeInBits() >= RetTy->getScalarSizeInBits())
          ContainedTy = Struct;
        else
          ContainedTy = RetTy;
        llvm::StructType *Union =
            llvm::StructType::create("union", ContainedTy);

        // Our body consists of exactly one `BasicBlock`.
        llvm::BasicBlock *BB = llvm::BasicBlock::Create(Ctx, "entry", Func);
        Builder.SetInsertPoint(BB);

        // Allocate the union.
        llvm::Value *S = Builder.CreateAlloca(Union, nullptr, "s");

        // Get pointer to the structure inside it.
        llvm::Value *SP =
            Builder.CreateBitCast(S, Struct->getPointerTo(), "sp");

        // Process arguments.
        for (llvm::Argument &Arg : Func->args()) {
          string ArgNo = to_string(Arg.getArgNo());

          // Load the argument.
          llvm::Value *AP =
              Builder.CreateAlloca(Arg.getType(), nullptr, "ap" + ArgNo);
          Builder.CreateStore(&Arg, AP);

          // Get pointer to the corresponding structure's element.
          llvm::Value *EP =
              Builder.CreateStructGEP(Struct, SP, Arg.getArgNo(), "ep" + ArgNo);

          // Store argument address in it.
          Builder.CreateStore(AP, EP);
        }

        // Call the DLL wrapper function.
        llvm::Value *VP = Builder.CreateBitCast(SP, VPTy, "vp");
        Builder.CreateCall(Wrapper, {VP});

        // Return.
        if (!RetTy->isVoidTy()) {

          // Get pointer to the return value inside the union.
          llvm::Value *RP =
              Builder.CreateBitCast(S, RetTy->getPointerTo(), "rp");

          // Load and return it.
          llvm::Value *R = Builder.CreateLoad(RP, "r");
          Builder.CreateRet(R);
        } else
          Builder.CreateRetVoid();

        // Verify correctness of the generated IR.
        string Error;
        llvm::raw_string_ostream OS(Error);
        if (verifyFunction(*Func, &OS)) {
          OS.flush();
          cerr << "Error while building Dylib function (" << Exp->Name
               << "): " << Error << '\n';
        }
      }

      // Compile the module. Inspired by LLVM tutorial:
      // https://llvm.org/docs/tutorial/LangImpl08.html.

      // Print out LLVM IR.
      if constexpr (OutputLLVMIR) {
        error_code EC;
        llvm::raw_fd_ostream IROutput((OutputDir / (LibNo + ".ll")).string(),
                                      EC, llvm::sys::fs::F_None);
        if (EC)
          cerr << "Error while creating LLVM output file (" << Lib.Name
               << "): " << EC.message() << '\n';
        else
          LibModule.print(IROutput, nullptr);
      }

      // Create `TargetMachine`.
      string Error;
      const llvm::Target *Target =
          llvm::TargetRegistry::lookupTarget(Module->getTargetTriple(), Error);
      if (!Target) {
        cerr << "Error while creating target (" << Lib.Name << "): " << Error
             << '\n';
        continue;
      }
      llvm::TargetMachine *TM = Target->createTargetMachine(
          Module->getTargetTriple(), "generic", "", llvm::TargetOptions(),
          /* RelocModel */ llvm::None);

      // Create output file.
      error_code EC;
      llvm::raw_fd_ostream Output((OutputDir / (LibNo + ".o")).string(), EC,
                                  llvm::sys::fs::F_None);
      if (EC) {
        cerr << "Error while creating output file (" << Lib.Name
             << "): " << EC.message() << '\n';
        continue;
      }

      // Emit object code.
      llvm::legacy::PassManager PM;
      if (TM->addPassesToEmitFile(PM, Output,
                                  llvm::TargetMachine::CGFT_ObjectFile)) {
        cerr << "Error: cannot emit object file.\n";
        continue;
      }
      PM.run(LibModule);
    }

    // Generate DLL wrappers.
    // TODO: Share code with iOS libraries generation.
    for (const DLLGroup &DLLGroup : DLLGroups) {
      for (const DLLEntry &DLL : DLLGroup.DLLs) {
        path DLLPath(DLLGroup.Dir / DLL.Name);

        // Prepare for IR generation.
        llvm::IRBuilder<> Builder(Ctx);
        llvm::Module LibModule(DLL.Name, Ctx);
        LibModule.setSourceFileName(DLLPath.string());

        // Target Windows.
        string Triple = "i386-pc-windows-msvc";
        string Error;
        const llvm::Target *Target =
            llvm::TargetRegistry::lookupTarget(Triple, Error);
        if (!Target) {
          cerr << "Error while creating target (" << DLL.Name << "): " << Error
               << '\n';
          continue;
        }

        // Create `TargetMachine`.
        llvm::TargetMachine *TM = Target->createTargetMachine(
            Triple, "generic", "", llvm::TargetOptions(),
            /* RelocModel */ llvm::None);

        // Configure LLVM `Module`.
        LibModule.setTargetTriple(Triple);
        LibModule.setDataLayout(TM->createDataLayout());

        // Since we are already generating so much wrappers, let's generate some
        // more. We create a Dylib file that exports the same functions as our
        // wrapper DLL, so that it can be then used by linker to link our iOS
        // stub Dylibs.
        llvm::IRBuilder<> DylibBuilder(Ctx);
        llvm::Module DylibModule(DLL.Name, Ctx);
        DylibModule.setSourceFileName(DLLPath.string());
        const llvm::Target *DylibTarget = llvm::TargetRegistry::lookupTarget(
            Module->getTargetTriple(), Error);
        if (!DylibTarget) {
          cerr << "Error while creating Dylib target (" << DLL.Name
               << "): " << Error << '\n';
          continue;
        }
        llvm::TargetMachine *DylibTM = DylibTarget->createTargetMachine(
            Module->getTargetTriple(), "generic", "", llvm::TargetOptions(),
            /* RelocModel */ llvm::None);
        DylibModule.setTargetTriple(Module->getTargetTriple());
        DylibModule.setDataLayout(Module->getDataLayout());

        // Since we are transferring data in memory across architectures,
        // they must have the same endianness for that to work.
        if (LibModule.getDataLayout().isLittleEndian() !=
            Module->getDataLayout().isLittleEndian()) {
          cerr << "Error: target platforms don't have the same endianness.\n";
        } else {
          assert(LibModule.getDataLayout().isBigEndian() ==
                     Module->getDataLayout().isBigEndian() &&
                 "Inconsistency in endianness.");
        }

        // Declare reference function.
        llvm::Function *RefFunc =
            !DLL.ReferenceFunc
                ? nullptr
                : llvm::Function::Create(
                      DLL.ReferenceFunc->Type, llvm::Function::ExternalLinkage,
                      '\01' + DLL.ReferenceFunc->Name, &LibModule);

        // Generate function wrappers.
        for (const ExportEntry *Exp : DLL.Exports) {
          assert(Exp->Status == ExportStatus::FoundInDLL &&
                 "Unexpected status of `ExportEntry`.");

          // Declarations.
          llvm::Function *Func = Exp->ObjCMethod
                                     ? nullptr
                                     : LibModule.getFunction('\01' + Exp->Name);
          if (!Func && !Exp->ObjCMethod)
            Func = llvm::Function::Create(Exp->Type,
                                          llvm::Function::ExternalLinkage,
                                          '\01' + Exp->Name, &LibModule);
          llvm::Function *Wrapper = llvm::Function::Create(
              WrapperTy, llvm::Function::ExternalLinkage,
              "\01$__ipaSim_wrapper_" + to_string(Exp->RVA), &LibModule);

          // Export the wrapper and import the original function.
          Wrapper->setDLLStorageClass(llvm::Function::DLLExportStorageClass);
          if (Func)
            Func->setDLLStorageClass(llvm::Function::DLLImportStorageClass);

          // Generate Dylib stub.
          llvm::Function *Stub = llvm::Function::Create(
              WrapperTy, llvm::Function::ExternalLinkage,
              "\01$__ipaSim_wrapper_" + to_string(Exp->RVA), &DylibModule);
          llvm::BasicBlock *StubBB =
              llvm::BasicBlock::Create(Ctx, "entry", Stub);
          DylibBuilder.SetInsertPoint(StubBB);
          DylibBuilder.CreateRetVoid();

          // TODO: Handle variadic functions.

          // Map parameter types to their pointers.
          vector<llvm::Type *> ParamPointers;
          ParamPointers.reserve(Exp->Type->getNumParams());
          for (llvm::Type *Ty : Exp->Type->params()) {
            ParamPointers.push_back(Ty->getPointerTo());
          }

          // Create the type of union that was used to store the function's
          // arguments and return value.
          llvm::StructType *Struct =
              llvm::StructType::create(ParamPointers, "struct");
          llvm::Type *RetTy = Exp->Type->getReturnType();
          llvm::Type *ContainedTy;
          if (RetTy->isVoidTy() ||
              Struct->getScalarSizeInBits() >= RetTy->getScalarSizeInBits())
            ContainedTy = Struct;
          else
            ContainedTy = RetTy;
          llvm::StructType *Union =
              llvm::StructType::create("union", ContainedTy);

          // Our body consists of exactly one `BasicBlock`.
          llvm::BasicBlock *BB =
              llvm::BasicBlock::Create(Ctx, "entry", Wrapper);
          Builder.SetInsertPoint(BB);

          // The union pointer is in the first argument.
          llvm::Value *UP = Wrapper->args().begin();

          // Get pointer to the structure inside the union.
          llvm::Value *SP =
              Builder.CreateBitCast(UP, Struct->getPointerTo(), "sp");

          // Process arguments.
          vector<llvm::Value *> Args;
          Args.reserve(Exp->Type->getNumParams());
          size_t ArgIdx = 0;
          for (llvm::Type *ArgTy : Exp->Type->params()) {
            string ArgNo = to_string(ArgIdx);

            // Load argument from the structure.
            llvm::Value *APP =
                Builder.CreateStructGEP(Struct, SP, ArgIdx, "app" + ArgNo);
            llvm::Value *AP = Builder.CreateLoad(APP, "ap" + ArgNo);
            llvm::Value *A = Builder.CreateLoad(AP, "a" + ArgNo);

            // Save the argument.
            Args.push_back(A);
            ++ArgIdx;
          }

          if (Exp->ObjCMethod) {
            // Objective-C methods are not exported, so we call them by
            // computing their address using their RVA.
            if (!DLL.ReferenceFunc) {
              cerr << "Error: no reference function, cannot emit Objective-C "
                      "method DLL wrappers ("
                   << DLL.Name << ").\n";
              continue;
            }

            // Add RVA to the reference function's address.
            llvm::Value *Addr = llvm::ConstantInt::getSigned(
                llvm::Type::getInt32Ty(Ctx), Exp->RVA - DLL.ReferenceFunc->RVA);
            llvm::Value *Ptr =
                Builder.CreateBitCast(RefFunc, llvm::Type::getInt8PtrTy(Ctx));
            llvm::Value *ComputedPtr = Builder.CreateInBoundsGEP(
                llvm::Type::getInt8Ty(Ctx), Ptr, Addr);
            llvm::Value *FP = Builder.CreateBitCast(
                ComputedPtr, Exp->Type->getPointerTo(), "fp");

            // Call the original DLL function.
            if (!RetTy->isVoidTy()) {
              llvm::Value *R = Builder.CreateCall(Exp->Type, FP, Args, "r");
              llvm::Value *RP =
                  Builder.CreateBitCast(UP, RetTy->getPointerTo(), "rp");
              Builder.CreateStore(R, RP);
            } else
              Builder.CreateCall(Exp->Type, FP, Args);
          } else if (!RetTy->isVoidTy()) {
            // Call the original DLL function.
            llvm::Value *R = Builder.CreateCall(Func, Args, "r");

            // Get pointer to the return value inside the union.
            llvm::Value *RP =
                Builder.CreateBitCast(UP, RetTy->getPointerTo(), "rp");

            // Save return value back into the structure.
            Builder.CreateStore(R, RP);
          } else {
            // Don't process return value of void function.
            Builder.CreateCall(Func, Args);
          }

          // Finish.
          Builder.CreateRetVoid();

          // Verify correctness of the generated IR.
          string Error;
          llvm::raw_string_ostream OS(Error);
          if (verifyFunction(*Wrapper, &OS)) {
            OS.flush();
            cerr << "Error while building DLL function (" << Exp->Name
                 << "): " << Error << '\n';
          }
        }

        // Print out LLVM IR.
        if constexpr (OutputLLVMIR) {
          error_code EC;
          llvm::raw_fd_ostream IROutput(
              (OutputDir / DLL.Name).replace_extension(".ll").string(), EC,
              llvm::sys::fs::F_None);
          if (EC)
            cerr << "Error while creating LLVM output file (" << DLL.Name
                 << "): " << EC.message() << '\n';
          else
            LibModule.print(IROutput, nullptr);
        }

        // Create output file.
        error_code EC;
        string OutputPath(
            (OutputDir / (DLL.Name)).replace_extension(".obj").string());
        llvm::raw_fd_ostream Output(OutputPath, EC, llvm::sys::fs::F_None);
        if (EC) {
          cerr << "Error while creating output file (" << DLL.Name
               << "): " << EC.message() << '\n';
          continue;
        }

        // Emit object code.
        llvm::legacy::PassManager PM;
        if (TM->addPassesToEmitFile(PM, Output,
                                    llvm::TargetMachine::CGFT_ObjectFile)) {
          cerr << "Error: cannot emit object file.\n";
          continue;
        }
        PM.run(LibModule);
        Output.close();

        // Link the wrapper DLL.
        string OutputDLL((WrappersDir / DLL.Name).string());
        string ImportLib(DLLPath.replace_extension(".lib").string());
        llvm::SmallVector<const char *, 256> Argv = {
            "clang.exe",       "-shared",          "-o",
            OutputDLL.c_str(), OutputPath.c_str(), ImportLib.c_str()};
        CompilerInstance DLLCI;
        DLLCI.createDiagnostics();

        // Inspired by `createInvocationFromCommandLine`.
        driver::Driver TheDriver(Argv[0], llvm::sys::getDefaultTargetTriple(),
                                 DLLCI.getDiagnostics());
        unique_ptr<driver::Compilation> C(TheDriver.BuildCompilation(Argv));
        if (!C || C->containsError()) {
          cerr << "Error while building `Compilation` to link a wrapper DLL ("
               << DLL.Name << ").\n";
          continue;
        }
        llvm::SmallVector<std::pair<int, const driver::Command *>, 4>
            FailingCommands;
        if (TheDriver.ExecuteCompilation(*C, FailingCommands)) {
          cerr << "Error while executing Clang to link a wrapper DLL ("
               << DLL.Name << ").\n";
          continue;
        }

        // Create the stub Dylib.
        string OOutputPath(
            (OutputDir / (DLL.Name)).replace_extension(".o").string());
        llvm::raw_fd_ostream OOutput(OOutputPath, EC, llvm::sys::fs::F_None);
        if (EC) {
          cerr << "Error while creating `.o` output file (" << DLL.Name
               << "): " << EC.message() << '\n';
          continue;
        }
        llvm::legacy::PassManager DylibPM;
        if (DylibTM->addPassesToEmitFile(
                DylibPM, OOutput, llvm::TargetMachine::CGFT_ObjectFile)) {
          cerr << "Error: cannot emit object file.\n";
          continue;
        }
        DylibPM.run(DylibModule);
        OOutput.close();
        string OutputDylib(
            (OutputDir / DLL.Name).replace_extension(".dll.dylib").string());
        string WrapperDLL("/Wrappers/" + DLL.Name);
        llvm::SmallVector<const char *, 256> StubArgv = {
            "clang.exe", "-target",
            // TODO: Don't hardcode target triple.
            "armv7s-apple-ios10", "-fuse-ld=lld", "-shared", "-o",
            OutputDylib.c_str(), OOutputPath.c_str(),
            // Don't emit error that symbol `dyld_stub_binder` is undefined.
            "-undefined", "warning",
            // But to do that, we cannot use two-level namespace.
            "-flat_namespace",
            // See [no-lsystem].
            "-no_lsystem",
            // Let's call this as the original DLL (in the Mach-O header), so
            // that our dynamic loader directly loads that.
            "-install_name", WrapperDLL.c_str()};
        CompilerInstance StubCI;
        StubCI.createDiagnostics();
        driver::Driver StubDriver(StubArgv[0],
                                  llvm::sys::getDefaultTargetTriple(),
                                  StubCI.getDiagnostics());
        unique_ptr<driver::Compilation> StubC(
            StubDriver.BuildCompilation(StubArgv));
        if (!StubC || StubC->containsError()) {
          cerr << "Error while building `Compilation` to link a stub Dylib ("
               << DLL.Name << ").\n";
          continue;
        }
        llvm::SmallVector<std::pair<int, const driver::Command *>, 4>
            StubFailingCommands;
        if (StubDriver.ExecuteCompilation(*StubC, StubFailingCommands)) {
          cerr << "Error while executing Clang to link a stub Dylib ("
               << DLL.Name << ").\n";
          continue;
        }
      }
    }

    // Generate iOS Dylibs.
    size_t DylibIdx = 0;
    for (const Dylib &Lib : iOSLibs) {
      string LibNo(to_string(DylibIdx++));

      string OutputDylib((DylibsDir / Lib.Name).string());
      string InputObject((OutputDir / (LibNo + ".o")).string());
      string LibraryPath(OutputDir.string());
      llvm::SmallVector<const char *, 256> DylibArgv = {
          "clang.exe", "-target",
          // TODO: Don't hardcode target triple.
          "armv7s-apple-ios10", "-fuse-ld=lld", "-shared", "-o",
          OutputDylib.c_str(), InputObject.c_str(),
          // Don't emit error that symbol `dyld_stub_binder` is undefined.
          "-undefined", "warning",
          // But to do that, we cannot use two-level namespace.
          "-flat_namespace",
          // See [no-lsystem].
          "-no_lsystem", "-install_name", Lib.Name.c_str(), "-L",
          LibraryPath.c_str()};

      // Add DLLs to link.
      set<const DLLEntry *> DLLs;
      vector<string> StringOwner;
      for (const ExportEntry *Exp : Lib.Exports) {
        if (Exp->DLL && DLLs.insert(Exp->DLL).second) {
          string DylibName(
              path(Exp->DLL->Name).replace_extension(".dll").string());
          const char *DylibCStr = DylibName.c_str();
          // Remove prefix `lib`.
          if (!DylibName.compare(0, 3, "lib"))
            DylibCStr = DylibCStr + 3;
          DylibArgv.push_back("-l");
          DylibArgv.push_back(DylibCStr);
          StringOwner.push_back(move(DylibName));
        }
      }

      // Create output directory.
      {
        error_code E;
        if (!create_directories(path(OutputDylib).parent_path(), E) && E) {
          cerr << "Fatal error while creating Dylib's output directory: "
               << E.message() << '\n';
          return 1;
        }
      }

      CompilerInstance DylibCI;
      DylibCI.createDiagnostics();
      driver::Driver DylibDriver(DylibArgv[0],
                                 llvm::sys::getDefaultTargetTriple(),
                                 DylibCI.getDiagnostics());
      unique_ptr<driver::Compilation> DylibC(
          DylibDriver.BuildCompilation(DylibArgv));
      if (!DylibC || DylibC->containsError()) {
        cerr << "Error while building `Compilation` to link a Dylib ("
             << Lib.Name << ").\n";
        continue;
      }
      llvm::SmallVector<std::pair<int, const driver::Command *>, 4>
          DylibFailingCommands;
      if (DylibDriver.ExecuteCompilation(*DylibC, DylibFailingCommands)) {
        cerr << "Error while executing Clang to link a Dylib (" << Lib.Name
             << ").\n";
        continue;
      }
    }

    // TODO: Again, just for testing.
    return 0;
  }

  export_list exps;

  // Discover `.tbd` files.
  {
    tbd_handler tbdh(exps);
    vector<string> tbdDirs{
        "./deps/apple-headers/iPhoneOS11.1.sdk/usr/lib/",
        "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/TextInput/"};
    for (auto &&dir : tbdDirs) {
      for (auto &&file : directory_iterator(dir)) {
        tbdh.handle_tbd_file(file.path().string());
      }
    }
    // Discover `.tbd` files inside frameworks.
    string frameworksDir =
        "./deps/apple-headers/iPhoneOS11.1.sdk/System/Library/Frameworks/";
    for (auto &&entry : directory_iterator(frameworksDir)) {
      if (entry.status().type() == file_type::directory &&
          !entry.path().extension().compare(".framework")) {
        tbdh.handle_tbd_file(
            (entry.path() / entry.path().filename().replace_extension(".tbd"))
                .string());
      }
    }
    cout << endl;
  }

  return 0;
}
