fn main() {
    let target = std::env::var("RUST_TARGET_NAME").unwrap_or_default();
    match target.as_str() {
        "TARGET_STAX" => println!("cargo:rustc-cfg=device_stax"),
        "TARGET_FLEX" => println!("cargo:rustc-cfg=device_flex"),
        "TARGET_APEX_P" => println!("cargo:rustc-cfg=device_apex_p"),
        "TARGET_NANOS2" => println!("cargo:rustc-cfg=device_nanos2"),
        "TARGET_NANOX" => println!("cargo:rustc-cfg=device_nanox"),
        _ => println!("cargo:rustc-cfg=device_nanos"), // default
    }
}
