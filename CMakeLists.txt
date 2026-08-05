cmake_minimum_required(VERSION 3.20)

project(RRRedirector C)


set(CMAKE_C_STANDARD 11)

# Rec Room is 64-bit; a 32-bit build silently fails to load. Guard against an x86 toolchain.
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Must build 64-bit. Import the amd64 VC env (vcvarsall.bat amd64) before cmake.")
endif()

# Where to deploy the built proxy. Point at your Rec Room install root; the deploy step below copies
# version.dll there. That single file is the whole payload -- see the note above the deploy step.
set(GAME_DIR "" CACHE PATH "Rec Room install root to deploy version.dll into")


add_library(redirector SHARED

    src/dllmain.c


    # Proxy loader (exports wrap the real system version.dll; DllMain starts the hook thread)
    src/proxy/version_proxy.c


    # Core
    src/core/logger.c
    src/core/config.c
    src/core/process.c


    # Hooks
    src/hooks/dns_hook.c
    src/hooks/connect_hook.c
    src/hooks/hook_manager.c


    # Memory
    src/memory/detour.c


    # Unity
    src/unity/module_watch.c
    src/unity/ssl_patch.c
    src/unity/http_rewrite.c
    src/unity/memcheck_patch.c
    src/unity/eac_patch.c


    # Utils
    src/utils/strings.c


    # Debug
    src/debug/api_logger.c
    src/debug/tls_logger.c
    src/debug/packet_logger.c
)


target_include_directories(
    redirector PRIVATE
    include
)



target_link_libraries(
    redirector

    ws2_32
    dbghelp
    psapi
)



# Output must be named version.dll so RecRoom.exe's VERSION.dll import resolves to us.
set_target_properties(
    redirector PROPERTIES

    OUTPUT_NAME "version"
    PREFIX ""
)


# The proxy loads the real system version.dll at runtime (see src/proxy/version_proxy.c), so there is
# nothing extra to materialize or ship -- version.dll is fully self-contained.


# Optional one-step deploy: -DGAME_DIR=... to copy version.dll into the game folder after build.
# The copy fails while Rec Room is running (DLL locked) -- close the game and rebuild.
if(GAME_DIR)
    add_custom_command(TARGET redirector POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:redirector>" "${GAME_DIR}/version.dll"
        COMMENT "Deploying version.dll to ${GAME_DIR}"
    )
endif()
