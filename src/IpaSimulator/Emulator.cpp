// Emulator.cpp: Implementation of class `Emulator`.

#include "ipasim/Emulator.hpp"

#include "ipasim/IpaSimulator.hpp"

#include <unicorn/unicorn.h>

using namespace ipasim;

Emulator::~Emulator() {
  if (UC)
    callUCStatic(uc_close(UC));
}

uint32_t Emulator::readReg(uc_arm_reg RegId) {
  uint32_t Result;
  callUC(uc_reg_read(UC, RegId, &Result));
  return Result;
}
void Emulator::writeReg(uc_arm_reg RegId, uint32_t Value) {
  callUC(uc_reg_write(UC, RegId, &Value));
}

void Emulator::mapMemory(uint64_t Addr, uint64_t Size, uc_prot Perms) {
  if (uc_mem_map_ptr(UC, Addr, Size, Perms, reinterpret_cast<void *>(Addr)))
    Log.error() << "couldn't map memory at 0x" << to_hex_string(Addr)
                << " of size 0x" << to_hex_string(Size) << Log.end();
}

void Emulator::start(uint64_t Addr) { callUC(uc_emu_start(UC, Addr, 0, 0, 0)); }

void Emulator::stop() { callUC(uc_emu_stop(UC)); }

void Emulator::hook(uc_hook_type Type, void *Handler, void *Instance) {
  uc_hook Hook;
  callUC(uc_hook_add(UC, &Hook, Type, Handler, Instance, 1, 0));
}

void Emulator::ignoreNextError() {
  assert(!IgnoreError && "Only one next error can be ignored.");
  IgnoreError = true;
}

uc_engine *Emulator::initUC() {
  uc_engine *UC;
  callUCStatic(uc_open(UC_ARCH_ARM, UC_MODE_ARM, &UC));
  return UC;
}

void Emulator::callUCStatic(uc_err Err) {
  if (Err != UC_ERR_OK)
    Log.error() << "unicorn failed: " << uc_strerror(Err) << Log.end();
}

void Emulator::callUC(uc_err Err) {
  if (Err != UC_ERR_OK) {
    if (IgnoreError)
      IgnoreError = false;
    else
      Log.error() << "unicorn failed at "
                  << Dyld.dumpAddr(readReg(UC_ARM_REG_PC)) << ": "
                  << uc_strerror(Err) << Log.end();
  }
}
