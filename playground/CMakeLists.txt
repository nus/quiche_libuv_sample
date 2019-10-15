cmake_minimum_required(VERSION 3.0)

add_executable(ssl_client
  ssl_client/ssl_client.c
)
target_link_libraries(ssl_client crypto)
target_link_libraries(ssl_client ssl)

add_executable(ssl_server
  ssl_server/ssl_server.c
)
target_link_libraries(ssl_server uv_a)
target_link_libraries(ssl_server crypto)
target_link_libraries(ssl_server ssl)
include_directories(../third_party/quiche/deps/boringssl/include)

add_executable(tcp_server
  tcp_server/tcp_server.c
)
target_link_libraries(tcp_server uv_a)

add_executable(udp_server
  udp_server/udp_server.c
)
target_link_libraries(udp_server uv_a)

add_executable(uv_timer
  uv_timer/uv_timer.c
)
target_link_libraries(uv_timer uv_a)

add_executable(uv_timer_stop
  uv_timer/uv_timer_stop.c
)
target_link_libraries(uv_timer_stop uv_a)

add_executable(uv_timer_again
  uv_timer/uv_timer_again.c
)
target_link_libraries(uv_timer_again uv_a)

include_directories("../third_party/libuv/include")
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
