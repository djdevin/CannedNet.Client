cmake_minimum_required(VERSION 3.20)

project(RRRedirector C)


set(CMAKE_C_STANDARD 11)

# Rec Room is 64-bit; a 32-bit build silently fails to load. Guard against an x86 toolchain.
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Must build 64-bit. Import the amd64 VC env (vcvarsall.bat amd64) before cmake.")
endif()

# Where to deploy the built proxy. Point at your Rec Room install root; the deploy step below copies
# wintrust.dll + wtrust_orig.dll there. See the note above the deploy step.
set(GAME_DIR "" CACHE PATH "Rec Room install root to deploy wintrust.dll into")


add_library(redirector SHARED

    src/dllmain.c


    # No proxy source: this build defeats every app-dir plant (System32 crypto pre-load; DXGIDisplays
    # not loaded in VR mode; UnityPlayer self-references and fail-fasts on a stub). With no anti-cheat
    # in-process, the vector is plain injection -- tools/launcher/launcher.exe suspended-launches
    # RecRoom.exe and LoadLibrary-injects this DLL before first instruction. DllMain (dllmain.c) starts
    # the hook thread. No exports needed.


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



# Plain injectable DLL: redirector.dll (injected by launcher.exe; no PE export/name requirement).
set_target_properties(
    redirector PROPERTIES

    OUTPUT_NAME "redirector"
    PREFIX ""
)


# The launcher that suspended-launches RecRoom.exe and injects redirector.dll. Built as a console EXE
# from the same toolchain so a single `cmake --build` produces both artifacts.
add_executable(launcher tools/launcher/launcher.c)
set_target_properties(launcher PROPERTIES OUTPUT_NAME "launcher")


# Optional one-step deploy: -DGAME_DIR=... copies redirector.dll + launcher.exe into the game root.
# The copy fails while Rec Room is running (DLLs locked) -- close the game and rebuild.
if(GAME_DIR)
    add_custom_command(TARGET redirector POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:redirector>" "${GAME_DIR}/redirector.dll"
        COMMENT "Deploying redirector.dll to ${GAME_DIR}"
    )
    add_custom_command(TARGET launcher POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:launcher>" "${GAME_DIR}/launcher.exe"
        COMMENT "Deploying launcher.exe to ${GAME_DIR}"
    )
endif()
