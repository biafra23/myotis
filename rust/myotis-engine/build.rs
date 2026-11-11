// A reproducible macOS dylib (#734, Part 5a): ld64 records the dylib's install
// name, which by default is its ABSOLUTE output path (the checkout path), so two
// builds in different directories differed in it and, through the layout, in
// most of the file. A fixed @rpath name instead. The hosts load this library by
// file path (JNA), so the install name plays no part at run time.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libmyotis_engine.dylib");
        // And, for a build without debug info, no debug map (#734, Part 5d).
        // Observed: two release builds of this dylib, in checkouts at
        // different paths, differed in LC_UUID and in the ad-hoc signature
        // that names it, and in nothing else; with -S they are identical.
        // The explanation that fits: the linker writes one stab per input
        // object that has DWARF (std's do, even when ours have none), with
        // the object's absolute path, and derives the UUID from its output,
        // stabs included; the release profile then strips them
        // (strip = "debuginfo", an external `strip -S` on Apple targets),
        // which leaves a UUID computed from bytes that are no longer there.
        // -S makes the linker not write the stabs, so the UUID is a function
        // of what ships.
        // Only without debug info (DEBUG is the profile's `debug`, as cargo
        // hands it to build scripts): a dev build, or a release build with
        // debug info asked for, keeps the map lldb, dsymutil and backtraces
        // read. myotis-bls and myotis-node do the same and point here.
        if std::env::var("DEBUG").as_deref() != Ok("true") {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-S");
        }
    }
}
