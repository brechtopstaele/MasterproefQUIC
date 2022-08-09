add_executable(protocol_identification protocol_identification.c)
target_link_libraries(protocol_identification LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS protocol_identification RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
