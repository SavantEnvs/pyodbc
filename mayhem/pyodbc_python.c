/* Plain interpreter built with the project's NORMAL flags: runs the upstream suite and the KAT probes
 * from test.sh as a /mayhem executable (so the oracle sabotage check can neuter it). */
#include <Python.h>

int main(int argc, char **argv) { return Py_BytesMain(argc, argv); }
