add_executable(rtcp_extraction rtcp_extraction.c)
target_link_libraries(rtcp_extraction LINK_PUBLIC peafowl pcap)
<<<<<<< HEAD
=======

if (ENABLE_DEMO)
    install(TARGETS rtcp_extraction RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
>>>>>>> SoftAtHome/master
