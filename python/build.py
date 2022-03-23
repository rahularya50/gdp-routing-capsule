import pathlib
import cffi

ffi = cffi.FFI()
this_dir = pathlib.Path().absolute().parent
h_file_name = this_dir / "crates/client/bindings.h"
with open(h_file_name) as h_file:
    ffi.cdef(h_file.read())

ffi.set_source(
    "gdp_client",
    '#include "bindings.h"',
    libraries=["libgdp_client"],
    library_dirs=[this_dir.joinpath("target/debug").as_posix()],
    extra_link_args=["-Wl,-rpath,."],
)
