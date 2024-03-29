# This macro can be used to install symlinks, which turns out to be
# non-trivial due to CMake version differences and limitations on how
# files can be installed when building binary packages.
#
# The rule for binary packaging is that files (including symlinks) must
# be installed with the standard CMake install() macro. We do so via
# a detour through CMAKE_CURRENT_BINARY_DIR: at install time we create
# the symlink there (using a tweaked name, to avoid collisions), then
# install that, and then clean it up to avoid leaving potential dangling
# symlinks in the build tree.
#
# The rule for non-binary packaging is that CMake 2.6 cannot install()
# symlinks, but can create the symlink at install-time via scripting.
# Though, we assume that CMake 2.6 isn't going to be used to generate
# packages because versions later than 2.8.3 are superior for that purpose.
#
#   _filepath: the absolute path to the file to symlink
#   _sympath: absolute path of the installed symlink

macro (InstallSymlink _filepath _sympath)
    get_filename_component(_symname ${_sympath} NAME)
    get_filename_component(_installdir ${_sympath} PATH)

    if (BINARY_PACKAGING_MODE)
        # We need install(CODE ...) here to run this at installation time.
        # execute_process would run at the configuration stage, making the
        # symlink potentially conflict with other actions by the caller.
        install(
            CODE "
            execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                ${_filepath}
                ${CMAKE_CURRENT_BINARY_DIR}/${_symname}.link)
        ")
        install(FILES ${CMAKE_CURRENT_BINARY_DIR}/${_symname}.link DESTINATION ${_installdir}
                RENAME ${_symname})
        install(CODE "file(REMOVE ${CMAKE_CURRENT_BINARY_DIR}/${_symname}.link)")
    else ()
        # scripting the symlink installation at install time should work
        # for CMake 2.6.x and 2.8.x
        install(
            CODE "
            if (\"\$ENV{DESTDIR}\" STREQUAL \"\")
                execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                                ${_filepath}
                                ${_installdir}/${_symname})
            else ()
                execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink
                                ${_filepath}
                                \$ENV{DESTDIR}/${_installdir}/${_symname})
            endif ()
        ")
    endif ()
endmacro (InstallSymlink)
