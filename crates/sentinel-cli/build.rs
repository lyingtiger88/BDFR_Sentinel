fn main() {
    println!("cargo:rerun-if-changed=../../assets/sentinel.ico");

    #[cfg(windows)]
    {
        if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
            let mut resource = winresource::WindowsResource::new();
            resource
                .set_icon("../../assets/sentinel.ico")
                .set("ProductName", "BDFR Sentinel")
                .set("CompanyName", "BDFR")
                .set("FileDescription", "BDFR Sentinel Command Line Scanner")
                .set("OriginalFilename", "bdfr-sentinel.exe")
                .set("LegalCopyright", "Copyright (c) BDFR");

            resource
                .compile()
                .expect("failed to compile BDFR Sentinel Windows resources");
        }
    }
}
