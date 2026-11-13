# Elk provenance and license

`src/interpreter.c` and `include/nucleovm/interpreter.h` were copied from the Elk 3.0.0 sources already present in `tripylon-firmware/llave-click-firmware` on 2026-11-13 and modified for NucleoVM. The original source is [Cesanta Elk](https://github.com/cesanta/elk), copyright Cesanta Software Limited.

The copied files retain their original notices and mark the NucleoVM modifications. Cesanta offers Elk under AGPLv3 or a separate commercial license. The NucleoVM fork is distributed under AGPLv3; the license text is in [COPYING](COPYING). A separate commercial license would need to be obtained from Cesanta if that is the intended distribution basis.

The first NucleoVM changes add tick accounting, a checked primitive registration path, and a C++ invocation wrapper. The original Tripylon firmware remains a separate prototype and is not updated by this fork.
