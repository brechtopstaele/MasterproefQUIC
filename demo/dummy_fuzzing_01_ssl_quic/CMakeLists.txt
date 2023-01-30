add_executable(dummy_fuzzing_01_ssl_quic dummy_fuzzing_01_ssl_quic.c)
target_link_libraries(dummy_fuzzing_01_ssl_quic LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS dummy_fuzzing_01_ssl_quic RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
