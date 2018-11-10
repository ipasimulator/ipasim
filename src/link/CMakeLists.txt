add_executable (link main.cpp)

target_link_libraries (link shlwapi)

add_dependencies (link prep)
