set (I 1)
foreach (asm_obj ${ASM_OBJECTS})
    execute_process (
        COMMAND "${SOURCE_DIR}/deps/objconv/objconv.exe"
            -fcoff -v1 "${asm_obj}" "${TARGET_DIR}/${I}.obj")
    math (EXPR I "${I}+1")
endforeach (asm_obj)
