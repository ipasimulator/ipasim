// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include <clang/Frontend/CompilerInstance.h>
#include <clang/Basic/TargetOptions.h>
#include <clang/Basic/TargetInfo.h>
#include <clang/Lex/PreprocessorOptions.h>
#include <clang/Parse/ParseAST.h>
#include <clang/AST/ASTContext.h>
#include <clang/Frontend/TextDiagnosticPrinter.h>

using namespace clang;
using namespace frontend;
using namespace std;

int main()
{
    // inspired by https://github.com/loarabia/Clang-tutorial/

    CompilerInstance ci;
    ci.createDiagnostics();

    //ci.getLangOpts().ObjC2 = 1;

    //ci.getHeaderSearchOpts().Sysroot = "C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/";
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/System/Library/Frameworks/", IncludeDirGroup::Angled, /*IsFramework*/ true, /*IgnoreSysRoot*/ false);
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/usr/include/", IncludeDirGroup::Angled, /*IsFramework*/ false, /*IgnoreSysRoot*/ false);

    auto targetOpts = make_shared<TargetOptions>();
    targetOpts->Triple = llvm::sys::getDefaultTargetTriple();
    ci.setTarget(TargetInfo::CreateTargetInfo(ci.getDiagnostics(), targetOpts)); // TODO: TargetInfo* should be deleted when not needed anymore

    ci.createFileManager();
    ci.createSourceManager(ci.getFileManager());
    ci.createPreprocessor(TranslationUnitKind::TU_Complete);
    //ci.getPreprocessorOpts().UsePredefines = false;

    ci.setASTConsumer(make_unique<ASTConsumer>());
    ci.createASTContext();
    ci.createSema(TranslationUnitKind::TU_Complete, nullptr);

    ci.getDiagnosticClient().BeginSourceFile(ci.getLangOpts(), &ci.getPreprocessor());

    const auto file = ci.getFileManager().getFile("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/System/Library/Frameworks/Foundation.framework/Headers/Foundation.h");
    ci.getSourceManager().setMainFileID(ci.getSourceManager().createFileID(file, SourceLocation(), SrcMgr::C_User));
    ParseAST(ci.getSema());
    ci.getASTContext().Idents.PrintStats();

    ci.getDiagnosticClient().EndSourceFile();

    return 0;
}
