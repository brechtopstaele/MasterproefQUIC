add_executable(protocol_identification_mc protocol_identification.cpp)
target_link_libraries(protocol_identification_mc LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS protocol_identification_mc RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
