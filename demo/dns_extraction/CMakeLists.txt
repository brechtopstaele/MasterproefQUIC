add_executable(dns_extraction dns_extraction.c)
target_link_libraries(dns_extraction LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS dns_extraction RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
