add_executable(dump_jpeg dump_jpeg.c)
target_link_libraries(dump_jpeg LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS dump_jpeg RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
