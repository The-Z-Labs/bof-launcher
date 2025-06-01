use std::process::Command;
use std::path::Path;
/// Build script assumes bof-launcher-win-x64.lib is in the lib/ directory.
fn main() {
    // Compile the BOF C file to object file
    compile_bof();

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

fn compile_bof() {
    let c_file = "bof/hello_bof.c";
    let obj_file = "bof/hello_bof.o";

    // Create bof directory if it doesn't exist
    std::fs::create_dir_all("bof").expect("Failed to create bof directory");

    // Tell Cargo to rerun this build script if the C file changes
    println!("cargo:rerun-if-changed={}", c_file);
    println!("cargo:rerun-if-changed=build.rs");

    // Check if we need to recompile (if source is newer than object file)
    let should_compile = !Path::new(obj_file).exists() ||
        is_source_newer(c_file, obj_file);

    if should_compile {
        println!("Compiling BOF: {} -> {}", c_file, obj_file);

        // Try different compilers in order of preference
        let compilers = ["cc", "x86_64-w64-mingw32-gcc", "gcc", "clang"];
        let mut success = false;

        for compiler in &compilers {
            let output = Command::new(compiler)
                .args(&[
                    "-c",                    // Compile only, don't link
                    "-o", obj_file,         // Output file
                    c_file,                 // Input file
                    "-fno-asynchronous-unwind-tables", // BOF compatibility
                    "-fno-ident",           // BOF compatibility
                    "-fPIC",                // Position independent code
                    "-Os",                  // Optimize for size
                ])
                .output();

            match output {
                Ok(output) if output.status.success() => {
                    println!("Successfully compiled BOF with {}", compiler);
                    success = true;
                    break;
                }
                Ok(output) => {
                    eprintln!("Compiler {} failed:", compiler);
                    eprintln!("stdout: {}", String::from_utf8_lossy(&output.stdout));
                    eprintln!("stderr: {}", String::from_utf8_lossy(&output.stderr));
                }
                Err(_) => {
                    // Compiler not found, try next one
                    continue;
                }
            }
        }

        if !success {
            panic!("Failed to compile BOF. Please ensure you have a C compiler installed (gcc, clang, or mingw)");
        }
    } else {
        println!("BOF object file is up to date");
    }
}

fn is_source_newer(source: &str, target: &str) -> bool {
    let source_meta = std::fs::metadata(source);
    let target_meta = std::fs::metadata(target);

    match (source_meta, target_meta) {
        (Ok(source_meta), Ok(target_meta)) => {
            source_meta.modified().unwrap() > target_meta.modified().unwrap()
        }
        _ => true, // If we can't get metadata, assume we need to recompile
    }
}