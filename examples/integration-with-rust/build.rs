/// Build script assumes bof-launcher-win-x64.lib is in the lib/ directory.
fn main() {
    // Link libraries
    println!("cargo:rustc-link-lib=ole32"); // Link ole32.lib
    println!("cargo:rustc-link-lib=lib/bof_launcher_win_x64"); // Link to your `.lib` file
    println!("cargo:rustc-link-lib=static=ucrt"); // Universal C Runtime

    // Add these additional runtime libraries for Windows
    println!("cargo:rustc-link-lib=libcmt"); // C runtime library
    println!("cargo:rustc-link-lib=libvcruntime"); // Visual C++ runtime
    println!("cargo:rustc-link-lib=kernel32"); // Windows kernel library
    println!("cargo:rustc-link-lib=user32"); // Windows user library
}