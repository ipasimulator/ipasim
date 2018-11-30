add_executable (link main.cpp)

add_prep_dep (link)

target_link_libraries (link shlwapi)
