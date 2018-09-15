// LLDBHelper.cpp

#include "LLDBHelper.hpp"

#include <lldb/API/SBDebugger.h>

using namespace lldb;
using namespace lldb_private;

LLDBHelper::LLDBHelper() {
  SBDebugger::Initialize();
  Debugger = Debugger::CreateInstance();
}
LLDBHelper::~LLDBHelper() {
  Debugger::Destroy(Debugger);
  SBDebugger::Terminate();
}
