macro(sokol_shader shd slang)
    set(args "{slang: '${slang}', compiler: '${CMAKE_C_COMPILER_ID}' }")
    fips_generate(TYPE SokolShader FROM ${shd} HEADER ${shd}.h OUT_OF_SOURCE ARGS ${args})
endmacro()

macro(sokol_shader_variant shd slang module defines)
    set(args "{slang: '${slang}', compiler: '${CMAKE_C_COMPILER_ID}', defines: '${defines}', module: '${module}' }")
    fips_generate(TYPE SokolShader FROM ${shd} HEADER ${shd}.${module}.h OUT_OF_SOURCE ARGS ${args})
endmacro()

macro(sokol_shader_with_reflection shd slang)
    set(args "{slang: '${slang}', compiler: '${CMAKE_C_COMPILER_ID}', reflection: true }")
    fips_generate(TYPE SokolShader FROM ${shd} HEADER ${shd}.h OUT_OF_SOURCE ARGS ${args})
endmacro()

macro(sokol_shader_variant_with_reflection shd slang module defines)
    set(args "{slang: '${slang}', compiler: '${CMAKE_C_COMPILER_ID}', defines: '${defines}', module: '${module}', reflection: true }")
    fips_generate(TYPE SokolShader FROM ${shd} HEADER ${shd}.${module}.h OUT_OF_SOURCE ARGS ${args})
endmacro()
