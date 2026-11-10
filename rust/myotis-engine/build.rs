// A reproducible macOS dylib (#734, Part 5a): ld64 records the dylib's install
// name, which by default is its ABSOLUTE output path (the checkout path), so two
// builds in different directories differed in it and, through the layout, in
// most of the file. A fixed @rpath name instead. The hosts load this library by
// file path (JNA), so the install name plays no part at run time.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libmyotis_engine.dylib");
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
