# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.25

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
CMAKE_SOURCE_DIR = /home/auxgrep/Desktop/network_malware/zeek-aux

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /home/auxgrep/Desktop/network_malware/zeek-aux/build

# Include any dependencies generated for this target.
include adtrace/CMakeFiles/adtrace.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include adtrace/CMakeFiles/adtrace.dir/compiler_depend.make

# Include the progress variables for this target.
include adtrace/CMakeFiles/adtrace.dir/progress.make

# Include the compile flags for this target's objects.
include adtrace/CMakeFiles/adtrace.dir/flags.make

adtrace/CMakeFiles/adtrace.dir/adtrace.c.o: adtrace/CMakeFiles/adtrace.dir/flags.make
adtrace/CMakeFiles/adtrace.dir/adtrace.c.o: /home/auxgrep/Desktop/network_malware/zeek-aux/adtrace/adtrace.c
adtrace/CMakeFiles/adtrace.dir/adtrace.c.o: adtrace/CMakeFiles/adtrace.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/home/auxgrep/Desktop/network_malware/zeek-aux/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building C object adtrace/CMakeFiles/adtrace.dir/adtrace.c.o"
	cd /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -MD -MT adtrace/CMakeFiles/adtrace.dir/adtrace.c.o -MF CMakeFiles/adtrace.dir/adtrace.c.o.d -o CMakeFiles/adtrace.dir/adtrace.c.o -c /home/auxgrep/Desktop/network_malware/zeek-aux/adtrace/adtrace.c

adtrace/CMakeFiles/adtrace.dir/adtrace.c.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing C source to CMakeFiles/adtrace.dir/adtrace.c.i"
	cd /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -E /home/auxgrep/Desktop/network_malware/zeek-aux/adtrace/adtrace.c > CMakeFiles/adtrace.dir/adtrace.c.i

adtrace/CMakeFiles/adtrace.dir/adtrace.c.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling C source to assembly CMakeFiles/adtrace.dir/adtrace.c.s"
	cd /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace && /usr/bin/cc $(C_DEFINES) $(C_INCLUDES) $(C_FLAGS) -S /home/auxgrep/Desktop/network_malware/zeek-aux/adtrace/adtrace.c -o CMakeFiles/adtrace.dir/adtrace.c.s

# Object files for target adtrace
adtrace_OBJECTS = \
"CMakeFiles/adtrace.dir/adtrace.c.o"

# External object files for target adtrace
adtrace_EXTERNAL_OBJECTS =

adtrace/adtrace: adtrace/CMakeFiles/adtrace.dir/adtrace.c.o
adtrace/adtrace: adtrace/CMakeFiles/adtrace.dir/build.make
adtrace/adtrace: /usr/lib/x86_64-linux-gnu/libpcap.so
adtrace/adtrace: adtrace/CMakeFiles/adtrace.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/home/auxgrep/Desktop/network_malware/zeek-aux/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking C executable adtrace"
	cd /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace && $(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/adtrace.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
adtrace/CMakeFiles/adtrace.dir/build: adtrace/adtrace
.PHONY : adtrace/CMakeFiles/adtrace.dir/build

adtrace/CMakeFiles/adtrace.dir/clean:
	cd /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace && $(CMAKE_COMMAND) -P CMakeFiles/adtrace.dir/cmake_clean.cmake
.PHONY : adtrace/CMakeFiles/adtrace.dir/clean

adtrace/CMakeFiles/adtrace.dir/depend:
	cd /home/auxgrep/Desktop/network_malware/zeek-aux/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /home/auxgrep/Desktop/network_malware/zeek-aux /home/auxgrep/Desktop/network_malware/zeek-aux/adtrace /home/auxgrep/Desktop/network_malware/zeek-aux/build /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace /home/auxgrep/Desktop/network_malware/zeek-aux/build/adtrace/CMakeFiles/adtrace.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : adtrace/CMakeFiles/adtrace.dir/depend

