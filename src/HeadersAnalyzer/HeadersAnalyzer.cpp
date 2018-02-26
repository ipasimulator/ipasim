// HeadersAnalyzer.cpp : Defines the entry point for the console application.
//

#include <iostream>
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

    //ci.getHeaderSearchOpts().Sysroot = "C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/";
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/System/Library/Frameworks/", IncludeDirGroup::Angled, /*IsFramework*/ true, /*IgnoreSysRoot*/ false);
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/headers/iPhoneOS11.1.sdk/usr/include/", IncludeDirGroup::Angled, /*IsFramework*/ false, /*IgnoreSysRoot*/ false);
    ci.getHeaderSearchOpts().AddPath("C:/Users/Jones/Files/Projects/IPASimulator/deps/clang/lib/Headers/", IncludeDirGroup::Angled, /*IsFramework*/ false, /*IgnoreSysRoot*/ false);
    //ci.getHeaderSearchOpts().ResourceDir = "C:/Users/Jones/Files/Projects/IPASimulator/deps/clang/lib/Headers/";

    auto targetOpts = make_shared<TargetOptions>();
    targetOpts->Triple = "armv7-apple-darwin"; // TODO: just a wild guess
    ci.setTarget(TargetInfo::CreateTargetInfo(ci.getDiagnostics(), targetOpts)); // TODO: TargetInfo* should be deleted when not needed anymore

    ci.createFileManager();
    ci.createSourceManager(ci.getFileManager());

    //ci.getPreprocessorOpts().UsePredefines = false;
    ci.createPreprocessor(TranslationUnitKind::TU_Complete);

    CompilerInvocation::setLangDefaults(ci.getLangOpts(), InputKind::ObjC, ci.getTarget().getTriple(), ci.getPreprocessorOpts());

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
