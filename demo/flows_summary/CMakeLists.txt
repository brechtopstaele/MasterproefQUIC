add_executable(flows_summary flows_summary.c)
target_link_libraries(flows_summary LINK_PUBLIC peafowl pcap)
add_executable(flows_summary_cpp flows_summary.cpp)
target_link_libraries(flows_summary_cpp LINK_PUBLIC peafowl pcap)

if (ENABLE_DEMO)
    install(TARGETS flows_summary RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
    install(TARGETS flows_summary_cpp RUNTIME DESTINATION ${DEMO_INSTALL_DIR})
endif (ENABLE_DEMO)
