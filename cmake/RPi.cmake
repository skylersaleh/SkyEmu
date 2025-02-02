# Function to check if a command exists
function(command_exists CMD RESULT_VAR)
    execute_process(COMMAND which ${CMD} OUTPUT_VARIABLE CMD_PATH RESULT_VARIABLE CMD_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(CMD_RESULT EQUAL 0)
        set(${RESULT_VAR} TRUE PARENT_SCOPE)
    else()
        set(${RESULT_VAR} FALSE PARENT_SCOPE)
    endif()
endfunction()

function(check_gles3_support SUPPORTS_GLES3)
    # Initialize variable
    set(SUPPORTS_GLES3 OFF PARENT_SCOPE)

    # Run the Bash one-liner to get the SoC version as a decimal number
    execute_process(
        COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/cmake/get_soc_version.sh
        OUTPUT_VARIABLE SOC_VERSION_DEC
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    message(STATUS, "soc verision: ${SOC_VERSION_DEC}")

    # Determine GLES3 support based on the SoC version
    if(SOC_VERSION_DEC GREATER_EQUAL 3)
        # BCM2711 or newer
        message(STATUS, "GLES3 supported")
        set(SUPPORTS_GLES3 ON PARENT_SCOPE)
    endif()
endfunction()
