fn main() {
    napi_build::setup();
    // A reproducible macOS addon (#734, Part 5a): ld64's default install name is
    // the dylib's ABSOLUTE output path (the checkout path); a fixed @rpath name
    // instead. Node loads the addon by file path, so it plays no part at run time.
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libmyotis_node.dylib");
        // And, for a build without debug info, no debug map, so that LC_UUID
        // is a function of what ships (#734, Part 5d): see
        // myotis-engine/build.rs, which has the reasoning.
        if std::env::var("DEBUG").as_deref() != Ok("true") {
            println!("cargo:rustc-cdylib-link-arg=-Wl,-S");
        }
    }
}
