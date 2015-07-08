# JabberWerxC #

An API for XMPP connectivity.

## Documentation ##

Documentation for the API is available at http://cisco.github.io/JabberWerxC/

## Dependencies ##

JabberWerxC can be built under Unix, Linux, OS X, or Windows, and has the following dependencies (configured using pkg-config):

* expat version 2.1.0 or later
* c-ares version 1.10 or later
* libevent version 2.0.21 or later
* libcurl version 7.31.0 or later (optional, for BOSH support)
* libidn version 1.28 or later (optional, for stringprep support)
* OpenSSL version 1.0 or later (optional, for TLS support.  Latest version strongly recommended)

## Building ##

JabberWerxC uses [CMake](http://www.cmake.org/) as its build system, and supports at least Mac OS X and Linux platforms.

### Prerequisites ###

JabberWerxC needs the following tools to build:

**REQUIRED**
*  CMake 2.8.11 or later
*  gcc 4.2.1 or later (*nix), or Visual Studio 2010 or later (windows)
* pkg-config

**OPTIONAL**
*  Doxygen 1.8.2 or later (optional, for API documentation generation)
*  lcov version 1.9 or later (*nix, optional, for code coverage reporting)
*  valgrind version 3.8.1 or later (*nix, optional, for memcheck reporting)

### Setting up Mac OS X ###

On OSX, if you're using [Homebrew](http://brew.sh/), you will need to do the following:

1. `brew install expat c-ares libevent libidn openssl`
2. `brew link --force openssl expat`

The latter command might cause other packages to fail in interesting ways; if so, you can undo it with `brew unlink openssl expat`.

### Setting up Unix/Linux ###
On Unix and Linux (but not on OS X), valgrind requires debug symbols in system libraries to accurately report errors or, in the case of glibc, to successfully execute. See discussion at:

http://forums.gentoo.org/viewtopic-p-6169375.html?sid=1dec34d64643af26295011dd33711245#6169375

### Generating the Build Environment ###

CMake will generate a build system appropriate for your platform.  First, install CMake for your platform.  Then, (*nix) in the `build` sub directory of the workspace root, execute:

 * (*nix) `./build.sh`
 * (Windows) run the cmake-gui tool and select the workspace root as the
    source directory and the `build` sub directory as the binary output directory

You can choose to generate Makefiles, Visual Studio projects, Eclipse projects, or any of the many other output targets that CMake supports.  Once you generate the build system for the first time, you should not need to run CMake explicitly again.  It will auto-detect when relevant files change and re-generate itself as necessary.

### Performing Builds ###

The resulting build system will have the following high-level targets:

| Target    | Description |
| --------- | ----------- |
| <default> | build the jabberwerx library and related code; no docs or packaging |
| test       | run unit tests |
| docs       | build and generate documentation |
| valgrind   | (non-Windows only) run unit tests under valgrind |
| package    | builds, tests, documents, and packages into a distributable archive |

There are also a number of options that can be set via ccmake or cmake-gui that affect the build.  Their default values are indicated below with a +/- prefix:

| Option | Description |
| ------ | ----------- |
| `+build_examples`    | build example applications along with the jabberwerx library |
| `-build_jwcunicode`  | build the jwcunicode example, whose additional build requirements are listed in src/examples/jwcunicode/README |
| `+build_tests`       | build unit tests along with the jabberwerx library; they are not run unless the 'test' target is explicitly specified |
| `+debug_symbols`     | keep debug symbols in the built code |
| `-do_coverage`       | create coverage report after the 'test' target completes |
| `+enable_bosh`       | if disabled, creation of BOSH streams will fail with an error code of JW_ERR_NOT_IMPLEMENTED and the curl library will not be built or distributed |
| `+enable_stringprep` | if disabled, jids are assumed to be ascii and are normalized by simple lowercasing; libidn is not built or distributed |
| `+enable_tls`        | if disabled, connections will fail if starttls is required and TLS-related functions will fail with an error code of JW_ERR_NOT_IMPLEMENTED |
| `-fatal_warnings`    | treat build warnings as errors; should be enabled by developers to ensure high code quality |
| `-optimized_build`   | pass optimization flags to the compiler |


### Build Example (*nix) ###

('$' indicates the console prompt):

```
  $ cd path/to/jwc
  $ ./build.sh
```

### Build Example (Windows) ###
Windows example:

1.  run `cmake-gui`
2.  select jwc root as source dir
3.  select `build` sub directory as binary dir
4.  click the Configure button
5.  select "Visual Studio 11" as the generator (For Visual Studio 2012)
6.  click the Generate button
7.  after generation is complete, browse to the `build` sub directory
8.  double-click on the "JabberWerxC" Visual Studio Solution file
9.  use the Visual Studio GUI to build the project
10. run `cmake-gui` again to change build options, if desired
11. re-run build in Visual Studio

###Notes###

- Xcode appears to crash while building third party code.  It is suggested to use the default Makefiles generator on OSX for the time being.
- The Ninja generator does not yet implement implicit dependencies, which the build system uses heavily.  However, building the individual targets works just fine.  For example, with make, the default 'all' target will build everything, but with ninja you have to build the targets individually:
  ```
    ninja thirdparty && ninja jabberwerx && ninja examples
  ```

## Copyrights ##

Portions created or assigned to Cisco Systems, Inc. are Copyright (c) 2010 Cisco Systems, Inc.  All Rights Reserved.

See LICENSE for details.
