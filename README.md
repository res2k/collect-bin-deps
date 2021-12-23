collect-bin-deps.py
===================
A tool to collect binary dependencies - typically shared libraries required by
an executable.

Requirements
------------
* `pefile`, `pyelftools` package

Usage
-----
Simplest case:

    collect-bin-deps.py -t <my exe file> <directory with dependency>...

Notes
-----
* The "debug info" doesn't try to locate the debug info file using the information
  contained in the binaries or so, it just looks for files with the same basename
  as a dependency but with extensions used for debug info files.

Limitations
-----------
* Currently supports Windows (PE) and Linux (ELF) binaries.

Inspiration
-----------
vcpkg can provide this functionality out of the box, realized with a
PowerShell script. collect-bin-deps.py was written from scratch to provide the
same functionality.
