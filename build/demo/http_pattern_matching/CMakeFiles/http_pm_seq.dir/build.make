# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.24

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /home/brecht/Downloads/peafowl-master

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/brecht/Downloads/peafowl-master/build

# Include any dependencies generated for this target.
include demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/compiler_depend.make

# Include the progress variables for this target.
include demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/progress.make

# Include the compile flags for this target's objects.
include demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/flags.make

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/flags.make
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o: /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/http_pm_seq.cpp
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brecht/Downloads/peafowl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o -MF CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o.d -o CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o -c /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/http_pm_seq.cpp

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.i"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/http_pm_seq.cpp > CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.i

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.s"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/http_pm_seq.cpp -o CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.s

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/flags.make
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o: /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/buffer.cc
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brecht/Downloads/peafowl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Building CXX object demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o -MF CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o.d -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o -c /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/buffer.cc

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.i"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/buffer.cc > CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.i

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.s"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/buffer.cc -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.s

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/flags.make
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o: /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/signatures.cc
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brecht/Downloads/peafowl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_3) "Building CXX object demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o -MF CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o.d -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o -c /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/signatures.cc

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.i"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/signatures.cc > CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.i

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.s"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/signatures.cc -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.s

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/flags.make
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o: /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/timer.cc
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brecht/Downloads/peafowl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_4) "Building CXX object demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o -MF CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o.d -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o -c /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/timer.cc

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.i"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/timer.cc > CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.i

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.s"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/timer.cc -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.s

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/flags.make
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o: /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/trie.cc
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/brecht/Downloads/peafowl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_5) "Building CXX object demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o -MF CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o.d -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o -c /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/trie.cc

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.i"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/trie.cc > CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.i

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.s"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && /usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching/pattern_matching_lib/trie.cc -o CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.s

# Object files for target http_pm_seq
http_pm_seq_OBJECTS = \
"CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o" \
"CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o" \
"CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o" \
"CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o" \
"CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o"

# External object files for target http_pm_seq
http_pm_seq_EXTERNAL_OBJECTS =

demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/http_pm_seq.cpp.o
demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/buffer.cc.o
demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/signatures.cc.o
demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/timer.cc.o
demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/pattern_matching_lib/trie.cc.o
demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/build.make
demo/http_pattern_matching/http_pm_seq: src/libpeafowl.so
demo/http_pattern_matching/http_pm_seq: /usr/local/lib64/libssl.so
demo/http_pattern_matching/http_pm_seq: /usr/local/lib64/libcrypto.so
demo/http_pattern_matching/http_pm_seq: demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/brecht/Downloads/peafowl-master/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_6) "Linking CXX executable http_pm_seq"
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/http_pm_seq.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/build: demo/http_pattern_matching/http_pm_seq
.PHONY : demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/build

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/clean:
	cd /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching && $(CMAKE_COMMAND) -P CMakeFiles/http_pm_seq.dir/cmake_clean.cmake
.PHONY : demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/clean

demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/depend:
	cd /home/brecht/Downloads/peafowl-master/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/brecht/Downloads/peafowl-master /home/brecht/Downloads/peafowl-master/demo/http_pattern_matching /home/brecht/Downloads/peafowl-master/build /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching /home/brecht/Downloads/peafowl-master/build/demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : demo/http_pattern_matching/CMakeFiles/http_pm_seq.dir/depend

