fn main() {
    napi_build::setup();
    // A reproducible macOS addon (#734, Part 5a): ld64's default install name is
    // the dylib's ABSOLUTE output path (the checkout path); a fixed @rpath name
    // instead. Node loads the addon by file path, so it plays no part at run time.
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libmyotis_node.dylib");
        // And no debug map (#734, Part 5d). The linker writes one stab per
        // input object (its path and mtime: for an LTO build, a temporary
        // directory with a random name) and derives the dylib's LC_UUID from
        // what it wrote, stabs included. The release profile then strips them
        // (strip = "debuginfo", an external `strip -S` on Apple targets), which
        // leaves a UUID computed from bytes that are no longer there: two
        // builds differed in the UUID, the ad-hoc signature that names it, and
        // nothing else. -S makes the linker not write the stabs, so the UUID
        // is a function of what ships.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-S");
    }
}
