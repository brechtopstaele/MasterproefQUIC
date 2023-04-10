add_executable(quic_extract_pcap quic_extraction_pcap.c)
target_link_libraries(quic_extract_pcap LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS quic_extract_pcap RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
