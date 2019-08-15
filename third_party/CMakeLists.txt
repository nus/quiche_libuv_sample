# For libuv
add_subdirectory(libuv)

# For uthash
add_library(uthash INTERFACE)
target_include_directories(uthash INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/uthash/include)

# For quiche
if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(CARGO_CMD cargo build)
    set(TARGET_DIR "debug")
else ()
    set(CARGO_CMD cargo build --release)
    set(TARGET_DIR "release")
endif ()

add_custom_target(quiche_build ALL
    COMMENT "Compiling quiche_build by cargo"
    COMMAND ${CARGO_CMD} --manifest-path ${CMAKE_CURRENT_SOURCE_DIR}/quiche/Cargo.toml --target-dir ${CMAKE_CURRENT_BINARY_DIR})

add_library(quiche STATIC IMPORTED GLOBAL)
add_dependencies(quiche quiche_build)
set_target_properties(quiche
    PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES
    ${CMAKE_CURRENT_SOURCE_DIR}/quiche/include)
set_target_properties(quiche
    PROPERTIES
    IMPORTED_LOCATION
    ${CMAKE_CURRENT_BINARY_DIR}/${TARGET_DIR}/libquiche.a)
