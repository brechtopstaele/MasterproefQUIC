add_executable(ssl_ja3 ssl_ja3.c)
target_link_libraries(ssl_ja3 LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS ssl_ja3 RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
