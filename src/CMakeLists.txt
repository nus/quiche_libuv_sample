cmake_minimum_required(VERSION 3.0)

add_executable(server
  server.cpp
  log.cpp
  udp_socket.cpp
  quic_server.cpp
  quic_connection.cpp
  quic_header_info.cpp
)

set_target_properties(server PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(server uv_a)
target_link_libraries(server quiche)
target_link_libraries(server uthash)
if(APPLE)
  target_link_libraries(server "-framework Security")
endif()

add_executable(client
  client.cpp
  log.cpp
  udp_socket.cpp
  quic_client.cpp
  quic_connection.cpp
  quic_header_info.cpp
)

set_target_properties(client PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(client uv_a)
target_link_libraries(client quiche)
target_link_libraries(client uthash)
if(APPLE)
  target_link_libraries(client "-framework Security")
endif()

add_executable(uv_client
  uv_client.cpp
  log.cpp
  quic_connection.cpp
  quic_header_info.cpp
)

set_target_properties(uv_client PROPERTIES
    CXX_STANDARD 11
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF
)

target_link_libraries(uv_client uv_a)
target_link_libraries(uv_client quiche)
if(APPLE)
  target_link_libraries(uv_client "-framework Security")
endif()

include_directories("../third_party/libuv/include")
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
