// A reproducible macOS dylib (#734, Part 5a): ld64 records the dylib's install
// name, which by default is its ABSOLUTE output path (the checkout path), so two
// builds in different directories differed in it and, through the layout, in
// most of the file. A fixed @rpath name instead. The hosts load this library by
// file path (JNA), so the install name plays no part at run time.
fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_VENDOR").as_deref() == Ok("apple") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/libmyotis_bls.dylib");
    }
}
