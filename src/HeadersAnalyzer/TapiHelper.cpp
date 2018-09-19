// TapiHelper.cpp

#include "TapiHelper.hpp"

#include "ErrorReporting.hpp"

#include <clang/Basic/FileSystemOptions.h>

using namespace clang;
using namespace llvm;
using namespace std;
using namespace tapi::internal;

TBDHandler::TBDHandler(HAContext &HAC)
    : HAC(HAC), FM(FileSystemOptions()), IFM(FM) {}

void TBDHandler::HandleFile(const string &Path) {
  // Check file.
  auto FileOrError = IFM.readFile(Path);
  if (!FileOrError) {
    reportError(Twine(toString(FileOrError.takeError())) + " (" + Path + ")");
    return;
  }
  InterfaceFileBase *FileBase = *FileOrError;
  // TODO: Shouldn't this be `armv7s`?
  if (!FileBase->getArchitectures().contains(Architecture::armv7)) {
    reportError(Twine("TBD file does not contain architecture ARMv7 (") + Path +
                ")");
    return;
  }
  auto *File = dynamic_cast<InterfaceFile *>(FileBase);
  if (!File) {
    reportError(Twine("interface file expected (") + Path + ")");
    return;
  }
  outs() << "Found TBD file (" << Path << ").\n";

  // Save the Dylib.
  DylibPtr Lib =
      HAC.iOSLibs.insert(HAC.iOSLibs.end(), {File->getInstallName()});

  // Find exports.
  for (Symbol *Sym : File->exports()) {
    // Determine symbol name.
    string Name;
    switch (Sym->getKind()) {
    case SymbolKind::ObjectiveCClass: {
      // Save class.
      auto Result(HAC.iOSClasses.insert({Sym->getName(), Lib}));
      if (!Result.second)
        reportError(Twine("duplicate class `") + Sym->getName() + "' in `" +
                    Result.first->second->Name + "' and in `" + Lib->Name +
                    "'");
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
      reportError(Twine("unrecognized symbol type (") +
                  Sym->getAnnotatedName() + ")");
      continue;
    }

    // Save export.
    ExportPtr Exp = HAC.iOSExps.find(Name);
    if (Exp != HAC.iOSExps.end())
      Lib->Exports.push_back(Exp);
    else
      Lib->Exports.push_back(HAC.addExport(move(Name)));
  }
}
