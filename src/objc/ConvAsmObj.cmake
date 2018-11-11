foreach (asm_obj ${ASM_OBJECTS})
    execute_process (
        COMMAND "${SOURCE_DIR}/deps/objconv/objconv.exe"
            -fcoff -v0 "${asm_obj}" "${asm_obj}-tmp")
    file (RENAME "${asm_obj}-tmp" "${asm_obj}")
endforeach (asm_obj)
