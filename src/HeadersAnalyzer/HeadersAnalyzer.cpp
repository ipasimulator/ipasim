// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

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

// Configuration.
enum class LibType { None = 0, Dylib = 0x1, DLL = 0x2, Both = 0x3 };
constexpr LibType WarnUninterestingFunctions = LibType::DLL;
constexpr bool OutputLLVMIR = true;

using namespace clang;
using namespace frontend;
using namespace std;
using namespace experimental::filesystem;
using namespace tapi::internal;

static constexpr bool operator&(LibType Value, LibType Flag) {
  return ((uint32_t)Value & (uint32_t)Flag) == (uint32_t)Flag;
}

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

class HeadersAnalyzer {
public:
  HeadersAnalyzer(CompilerInstance &ci, export_list &exps, ostream &output)
      : ci_(ci), exps_(exps), after_first_(false), output_(output),
        mctx_(nullptr) {}
  ~HeadersAnalyzer() {
    if (mctx_) {
      delete mctx_;
    }
  }
  void Initialize() {
    // TODO: Is this mangling what Apple uses?
    mctx_ =
        ItaniumMangleContext::create(ci_.getASTContext(), ci_.getDiagnostics());
  }
  void VisitFunction(FunctionDecl &f) {
    const FunctionProtoType *fpt =
        f.getFunctionType()->getAs<FunctionProtoType>();

    // Ignore templates.
    if (fpt->isDependentType()) {
      return;
    }

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
    } else {
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

      // Just skip it if it is exactly the same function or we already know it's
      // overloaded.
      // TODO: Maybe just delete overloaded functions from `exps_`.
      if (it->second.status == export_status::Overloaded ||
          // TODO: Does this work?
          it->second.decl->getFunctionType()
                  ->getAs<FunctionProtoType>()
                  ->desugar() == fpt->desugar()) {
        return;
      }

      // Otherwise, it's an overloaded function and we can't support those.
      it->second.status = export_status::Overloaded;
      if (it->second.status == export_status::Generated) {
        // TODO: Such function was generated, but we must ignore it!
        cerr << "Fatal error: function is overloaded accross headers (" << name
             << ")." << endl;
      } else {
        cerr << "Error: function is overloaded (" << name << ")." << endl;
      }
      return;
    }
    it->second.status = export_status::Found;

    // TODO: Check that Apple's and WinObjC's signatures of the function are
    // equal.

    // Save function, it will be needed later for code generation.
    // TODO: Won't this get deleted too early?
    it->second.decl = &f;
  }
  // TODO: Merge dispatching code for functions with the same signature.
  void GenerateCode() {
    for (auto &&exp : exps_) {
      if (exp.second.status == export_status::Found) {
        exp.second.status = export_status::Generated;

        const FunctionDecl &f = *exp.second.decl;
        const FunctionProtoType *fpt =
            f.getFunctionType()->getAs<FunctionProtoType>();
        const string &name = exp.first;
        string identifier = f.getIdentifier()->getName().str();

        // TODO: Don't do any of the following code, implement and use
        // `cc_mapper` instead.

        if (after_first_) {
          output_ << "else ";
        } else {
          after_first_ = true;
        }
        // TODO: Don't compare `module` with symbol name!
        output_ << "if (!std::strcmp(module, \"" << name << "\")) {" << endl;

        // Our printing policy for types. See [pretty-print].
        PrintingPolicy pp(ci_.getASTContext().getPrintingPolicy());
        pp.PolishForInlineDeclaration = true;

        // We will simply assume arguments are in r0-r3 or on stack for
        // starters. Inspired by /res/arm/IHI0042F_aapcs.pdf (AAPCS),
        // section 5.5 Parameter Passing.

        uint8_t r = 0;  // register offset (AAPCS's NCRN)
        uint64_t s = 0; // stack offset (relative AAPCS's NSAA)

        uint32_t i = 0;
        for (auto &pt : fpt->param_types()) {
          uint64_t bytes =
              ci_.getASTContext().getTypeSizeInChars(pt).getQuantity();
          assert(bytes > 0 && "non-trivial type expected");

          output_ << "ARG(" << to_string(i) << ", " << pt.getAsString(pp) << ")"
                  << endl;

          // Copy data from registers and/or stack into the argument.
          while (bytes) {
            if (r == 4) {
              // We used all the registers, this argument is on the stack.
              // Note that r13 is the stack pointer.
              // TODO: Handle unicorn errors.
              // TODO: Encapsulate this into a macro.
              // TODO: Maybe read the memory at the SP directly.
              output_ << "uc_mem_read(uc, r13, c" << to_string(i) << " + "
                      << to_string(s) << ", " << to_string(bytes) << ");"
                      << endl;
              s += bytes;
              break; // We copied all the data.
            } else {
              output_ << "p" << to_string(i) << "[" << to_string(r) << "] = r"
                      << to_string(r) << ";" << endl;
              ++r;

              if (bytes <= 4) {
                break;
              }
              bytes -= 4;
            }
          }

          ++i;
        }

        // Call the function through a function pointer saved in argument named
        // "address".
        {
          // Print declaration of the function.
          DeclStmt decl(DeclGroupRef(const_cast<FunctionDecl *>(&f)),
                        SourceLocation{}, SourceLocation{});
          llvm::raw_os_ostream s(output_);
          decl.printPretty(s, nullptr, pp);
          s.flush();
        }
        if (!fpt->getReturnType()->isVoidType()) {
          output_ << "RET(";
        }
        output_ << "reinterpret_cast<decltype(&" << identifier
                << ")>(address)(";
        for (i = 0; i != fpt->getNumParams(); ++i) {
          if (i != 0) {
            output_ << ", ";
          }
          output_ << "std::move(*v" << to_string(i) << ")";
        }
        if (!fpt->getReturnType()->isVoidType()) {
          output_ << ")";
        }
        output_ << ");" << endl;

        // Handle the return value.
        if (!fpt->getReturnType()->isVoidType()) {
          r = 0;
          uint64_t bytes = ci_.getASTContext()
                               .getTypeSizeInChars(fpt->getReturnType())
                               .getQuantity();
          assert(bytes > 0 && "non-trivial return type expected");

          for (;;) {
            if (r == 4) {
              output_ << "// TODO: Return value is too big!" << endl;
            }
            if (r >= 4) {
              output_ << "// ";
            }

            output_ << "r" << to_string(r) << " = retp[" << to_string(r) << "];"
                    << endl;
            ++r;

            if (bytes <= 4) {
              break;
            }
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
};

template <typename T>
class CustomASTVisitor : public RecursiveASTVisitor<CustomASTVisitor<T>> {
public:
  CustomASTVisitor(T &ha) : ha_(ha) {}
  bool VisitFunctionDecl(FunctionDecl *f) { // TODO: override
    // TODO: Should we call parent's implementation?
    // if (!RecursiveASTVisitor::VisitFunctionDecl(f)) { return false; }

    ha_.VisitFunction(*f);
    return true;
  }

private:
  T &ha_;
};

template <typename T> class CustomASTConsumer : public ASTConsumer {
public:
  CustomASTConsumer(T &ha) : v_(ha), ha_(ha) {}
  bool HandleTopLevelDecl(DeclGroupRef d) override {
    for (auto b : d) {
      v_.TraverseDecl(b);
    }
    return true;
  }

private:
  CustomASTVisitor<T> v_;
  T &ha_;
};

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

class iOSHeadersAnalyzer {
public:
  iOSHeadersAnalyzer(const CompilerInstance &CI, export_list &Exps)
      : CI(CI), Exps(Exps) {
    // TODO: Is this mangling what Apple uses?
    Mangle = CI.getASTContext().createMangleContext();
  }
  ~iOSHeadersAnalyzer() { delete Mangle; }
  // TODO: Rename to `visitFunction` (with lowercase "v").
  void VisitFunction(FunctionDecl &Func) {
    const FunctionProtoType *FPT =
        Func.getFunctionType()->getAs<FunctionProtoType>();

    // Ignore templates.
    if (FPT->isDependentType())
      return;

    // Get function's mangled name. Inspired by
    // https://github.com/llvm-mirror/clang/blob/1bc73590ad1335313e8f262393547b8af67c9167/lib/Index/CodegenNameGenerator.cpp#L150.
    string FName;
    if (Mangle->shouldMangleDeclName(&Func)) {
      llvm::raw_string_ostream OS(FName);
      if (const auto *CtorD = dyn_cast<CXXConstructorDecl>(&Func))
        Mangle->mangleCXXCtor(CtorD, Ctor_Complete, OS);
      else if (const auto *DtorD = dyn_cast<CXXDestructorDecl>(&Func))
        Mangle->mangleCXXDtor(DtorD, Dtor_Complete, OS);
      else
        Mangle->mangleName(&Func, OS);
      OS.flush();
    } else {
      // TODO: Even though our mangler says C functions shouldn't be mangled,
      // they seem to actually be mangled on iOS.
      if (Func.getLanguageLinkage() == CLanguageLinkage)
        FName = "_";
      FName += Func.getIdentifier()->getName().str();
    }

    // Skip functions that don't interest us.
    auto Exp = Exps.find(FName);
    if (Exp == Exps.end())
      return;

    // TODO: Do something with the function.
    cout << FName << '\n';
  }

private:
  export_list Exps;
  const CompilerInstance &CI;
  MangleContext *Mangle;
};

enum class ExportStatus { NotFound = 0, Found, Overloaded, FoundInDLL };

struct ExportEntry {
  ExportEntry(string Name)
      : Name(Name), Status(ExportStatus::NotFound), RVA(0), Type(nullptr) {}

  string Name;
  mutable ExportStatus Status;
  mutable uint32_t RVA;
  mutable llvm::FunctionType *Type;

  bool operator<(const ExportEntry &Other) const { return Name < Other.Name; }
};

using ExportList = set<ExportEntry>;

struct Dylib {
  string Name;
  vector<const ExportEntry *> Exports;
};

// TODO: Is this correct? See also <llvm/IR/Mangler.h>.
class iOSMangler {
public:
  iOSMangler(const CompilerInstance &CI)
      : Mangle(CI.getASTContext().createMangleContext()) {}
  ~iOSMangler() { delete Mangle; }
  string MangleFunctionName(const FunctionDecl &Func) {
    // Get function's mangled name. Inspired by
    // https://github.com/llvm-mirror/clang/blob/1bc73590ad1335313e8f262393547b8af67c9167/lib/Index/CodegenNameGenerator.cpp#L150.
    string FName;
    if (Mangle->shouldMangleDeclName(&Func)) {
      llvm::raw_string_ostream OS(FName);
      if (const auto *CtorD = dyn_cast<CXXConstructorDecl>(&Func))
        Mangle->mangleCXXCtor(CtorD, Ctor_Complete, OS);
      else if (const auto *DtorD = dyn_cast<CXXDestructorDecl>(&Func))
        Mangle->mangleCXXDtor(DtorD, Dtor_Complete, OS);
      else
        Mangle->mangleName(&Func, OS);
      OS.flush();
    } else {
      // TODO: Even though our mangler says C functions shouldn't be mangled,
      // they seem to actually be mangled on iOS.
      if (Func.getLanguageLinkage() == CLanguageLinkage)
        FName = "_";
      FName += Func.getIdentifier()->getName().str();
    }
    return std::move(FName);
  }

private:
  MangleContext *Mangle;
};

// See `iOSHeadersAction`.
class iOSHeadersConsumer : public ASTConsumer {
public:
  iOSHeadersConsumer(const CompilerInstance &CI, ExportList &Exps)
      : CI(CI), Exps(Exps) {}
  bool HandleTopLevelDecl(DeclGroupRef DeclGroup) override {
    for (const auto *Decl : DeclGroup) {
      if (auto *Func = llvm::dyn_cast<FunctionDecl>(Decl)) {
        HandleFunctionDecl(Func);
      }
    }
    return true;
  }

private:
  void HandleFunctionDecl(const FunctionDecl *Func) {
    // Handle only functions that interest us.
    string MangledName = iOSMangler(CI).MangleFunctionName(*Func);
    auto Exp = Exps.find(MangledName);
    if (Exp == Exps.end())
      return;

    // TODO: Remove if we won't use it.
    cout << "F: " << MangledName << '\n';
  }

private:
  const CompilerInstance &CI;
  ExportList &Exps;
};

// This action will "use" functions from headers, so that they are compiled into
// LLVM. Otherwise, they would be thrown out as unused, but we need them to
// inspect their calling conventions later.
class iOSHeadersAction : public ASTFrontendAction {
public:
  iOSHeadersAction(ExportList &Exps) : Exps(Exps) {}

  std::unique_ptr<clang::ASTConsumer>
  CreateASTConsumer(CompilerInstance &CI, llvm::StringRef InFile) override {
    return llvm::make_unique<iOSHeadersConsumer>(CI, Exps);
  }

private:
  ExportList &Exps;
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

using ClassExportList = map<string, size_t>;

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

struct DLLEntry {
  DLLEntry(string Name) : Name(Name) {}

  string Name;
  vector<const ExportEntry *> Exports;
};

struct DLLGroup {
  path Dir;
  vector<DLLEntry> DLLs;
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

          // Find the corresponding iOS export.
          auto Exp = iOSExps.find(Func->getUndecoratedName());
          if (Exp == iOSExps.end() || Exp->Status != ExportStatus::Found) {
            if constexpr (WarnUninterestingFunctions & LibType::DLL) {
              cerr << "Warning: found uninteresting function in DLL ("
                   << Func->getUndecoratedName()
                   << "). Isn't that interesting?\n";
            }
            continue;
          }
          Exp->Status = ExportStatus::FoundInDLL;
          Exp->RVA = Func->getRelativeVirtualAddress();
          DLL.Exports.push_back(&*Exp);

          // Verify that the function has the same signature as the iOS one.
          if (!TC.areEquivalent(Exp->Type, *Func)) {
            cerr << "Error: functions' signatures are not equivalent ("
                 << Exp->Name << ").\n";
          }
        }
      }
    }

    // Create output directory.
    path OutputDir("./src/HeadersAnalyzer/Debug/");
    {
      error_code E;
      if (!create_directories(OutputDir, E) && E) {
        cerr << "Fatal error while creating output directory: " << E.message()
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
        if (Exp->Status != ExportStatus::FoundInDLL)
          continue;

        // Declaration. Note that we add prefix `\01`, so that the name doesn't
        // get mangled since it already is. LLVM will remove this prefix before
        // emitting object code for the function.
        llvm::Function *Func =
            llvm::Function::Create(Exp->Type, llvm::Function::ExternalLinkage,
                                   '\01' + Exp->Name, &LibModule);

        // DLL wrapper declaration.
        llvm::Function *Wrapper = llvm::Function::Create(
            WrapperTy, llvm::Function::ExternalLinkage,
            "\01$__ipaSim_wrapper_" + Exp->Name, &LibModule);

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
          cerr << "Error while building function (" << Exp->Name
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

        // Generate function wrappers.
        for (const ExportEntry *Exp : DLL.Exports) {
          assert(Exp->Status == ExportStatus::FoundInDLL &&
                 "Unexpected status of `ExportEntry`.");

          // Declarations.
          llvm::Function *Func =
              llvm::Function::Create(Exp->Type, llvm::Function::ExternalLinkage,
                                     '\01' + Exp->Name, &LibModule);
          llvm::Function *Wrapper = llvm::Function::Create(
              WrapperTy, llvm::Function::ExternalLinkage,
              "\01$__ipaSim_wrapper_" + Exp->Name, &LibModule);
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

  // Create output files.
  // TODO: This won't create the /out/ directory if it doesn't exist!
  fstream invokes("./out/invokes.inc", fstream::out);
  fstream headers("./out/headers.inc", fstream::out);

  // Analyze headers.
  // TODO: Maybe use `/deps/WinObjC/.apianalyzer/` configuration files.
  // TODO: Parse headers just for deprecated attributes and `@Status` comments.
  vector<string> headerPaths{"./deps/WinObjC/include/Foundation/Foundation.h",
                             "./deps/WinObjC/tools/include/objc/objc-arc.h",
                             "./deps/WinObjC/tools/include/objc/message.h"};
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
        "-I",
        "./deps/WinObjC/include",
        "-I",
        "./deps/WinObjC/include/Platform/Universal Windows",
        "-I",
        "./deps/WinObjC/Frameworks/include",
        "-I",
        "./deps/WinObjC/include/xplat",
        "-I",
        "./deps/WinObjC/tools/include/WOCStdLib",
        "-I",
        "./deps/WinObjC/tools/include",
        "-I",
        "./deps/WinObjC/tools/Logging/include",
        "-I",
        "./deps/WinObjC/tools/include/xplat",
        "-I",
        "./deps/WinObjC/tools/deps/prebuilt/include",
        "-x",
        "objective-c++",
        headerPath.c_str()};
    ci.setInvocation(createInvocationFromCommandLine(llvm::makeArrayRef(args)));

    // TODO: TargetInfo* should be deleted when not needed anymore. Should it,
    // though?
    ci.setTarget(TargetInfo::CreateTargetInfo(ci.getDiagnostics(),
                                              ci.getInvocation().TargetOpts));

    ci.createFileManager();
    ci.createSourceManager(ci.getFileManager());

    // ci.getPreprocessorOpts().UsePredefines = false;
    ci.createPreprocessor(TranslationUnitKind::TU_Complete);
    HeadersAnalyzer ha(ci, exps, invokes);
    ci.setASTConsumer(make_unique<CustomASTConsumer<HeadersAnalyzer>>(ha));
    ci.createASTContext();
    ha.Initialize();
    ci.createSema(TranslationUnitKind::TU_Complete, nullptr);

    const auto file = ci.getFileManager().getFile(headerPath);
    ci.getSourceManager().setMainFileID(ci.getSourceManager().createFileID(
        file, SourceLocation(), SrcMgr::C_User));

    ci.getDiagnosticClient().BeginSourceFile(ci.getLangOpts(),
                                             &ci.getPreprocessor());
    ParseAST(ci.getSema(), /*PrintStats*/ false, /*SkipFunctionBodies*/ true);
    ci.getDiagnosticClient().EndSourceFile();

    ha.GenerateCode();
  }

  return 0;
}
