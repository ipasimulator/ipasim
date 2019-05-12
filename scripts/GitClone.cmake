# Called from `./CMakeLists.txt`. This is a workaround for bug
# <https://github.com/git-for-windows/git/issues/1661> which appears when trying
# to clone Git repositories using `ExternalProject_Add`.

file (REMOVE_RECURSE "${TARGET_DIR}")

execute_process (COMMAND git clone --recurse-submodules "${REPO}"
    "${TARGET_DIR}")

execute_process (COMMAND git checkout "${TAG}"
    WORKING_DIRECTORY "${TARGET_DIR}")
