// TapiHelper.cpp

#include "ipasim/TapiHelper.hpp"

#include "ipasim/ErrorReporting.hpp"

#include <clang/Basic/FileSystemOptions.h>

using namespace clang;
using namespace ipasim;
using namespace llvm;
using namespace std;
using namespace tapi::internal;

TBDHandler::TBDHandler(HAContext &HAC)
    : HAC(HAC), FM(FileSystemOptions()), IFM(FM) {}

void TBDHandler::handleFile(const string &Path) {
  bool HasTBDExtension = filesystem::path(Path).extension() == ".tbd";

  // Check file.
  auto FileOrError = IFM.readFile(Path);
  if (!FileOrError) {
    // If the file hasn't `.tbd` extension, it's OK that we cannot read it.
    if (HasTBDExtension)
      Log.error() << toString(FileOrError.takeError()) << " (" << Path << ")"
                  << Log.end();
    else
      consumeError(FileOrError.takeError());
    return;
  }
  // If we can read it and it hasn't `.tbd` extensions, well, that's weird.
  if (!HasTBDExtension)
    Log.warning() << "TBD file without `.tbd` extension (" << Path << ")"
                  << Log.end();
  InterfaceFileBase *FileBase = *FileOrError;
  // TODO: Shouldn't this be `armv7s`?
  if (!FileBase->getArchitectures().contains(Architecture::armv7)) {
    Log.error() << "TBD file does not contain architecture ARMv7 (" << Path
                << ")" << Log.end();
    return;
  }
  auto *File = dynamic_cast<InterfaceFile *>(FileBase);
  if (!File) {
    Log.error() << "interface file expected (" << Path << ")" << Log.end();
    return;
  }

  // Save the Dylib.
  auto InsertPair(HAC.iOSLibs.insert({File->getInstallName()}));
  if (!InsertPair.second) {
    // Ignore Dylibs with already-found install name, the corresponding TBD
    // files should be identical.
    return;
  }
  DylibPtr Lib(InsertPair.first);

  // Find exports.
  for (Symbol *Sym : File->exports()) {
    // Determine symbol name.
    string Name;
    switch (Sym->getKind()) {
    case SymbolKind::ObjectiveCClass: {
      // HACK: Get original name with leading underscore that was dropped - see
      // `TextStub_v2.cpp`, line 301, commit `a92576e0`.
      llvm::StringRef OriginalName(Sym->getName().data() - 1,
                                   Sym->getName().size() + 1);

      // Save class.
      auto Class = HAC.iOSClasses.insert(OriginalName.str()).first;
      Class->Dylibs.push_back(Lib);

      // Also let it appear as if special Objective-C symbols are exported even
      // though they might not actually be listed in the TBD file.
      addExport(Lib, "_OBJC_CLASS_$" + OriginalName.str());
      addExport(Lib, "_OBJC_METACLASS_$" + OriginalName.str());
      continue;
    }
    case SymbolKind::ObjectiveCInstanceVariable:
    case SymbolKind::ObjectiveCClassEHType:
      // Skip `ObjectiveC*` symbols, since they aren't functions.
      break;
    case SymbolKind::GlobalSymbol:
      Name = Sym->getName();
      break;
    default:
      Log.error() << "unrecognized symbol type (" << Sym->getAnnotatedName()
                  << ")" << Log.end();
      continue;
    }

    // Save export.
    addExport(Lib, move(Name));
  }
}

void TBDHandler::addExport(DylibPtr Lib, string &&Name) {
  ExportPtr Exp = HAC.iOSExps.find(Name);
  if (Exp == HAC.iOSExps.end())
    Exp = HAC.addExport(move(Name));
  Lib->Exports.push_back(Exp);
}
