use std::ffi::c_void;
use std::ptr::null_mut;

#[repr(C)]
#[derive(Debug, Clone)]
pub struct BofObjectHandle {
    bits: u32,
}

#[link(name = "lib/bof_launcher_win_x64", kind = "static")]
unsafe extern "C" {
    pub fn bofObjectInitFromMemory(
        file_data_ptr: *const u8,    // Matches `const unsigned char*`
        file_data_len: i32,          // Matches `int`
        out_bof_handle: *mut BofObjectHandle, // Matches `BofObjectHandle*`, output can't be NULL
    ) -> i32;

    pub fn bofObjectRun(
        bof_handle: BofObjectHandle,
        arg_data_ptr: *const c_void,
        arg_data_len: i32,
        out_bof_handle: &mut *mut c_void,
    ) -> i32;
}
const BOF_OBJECT: &[u8] = include_bytes!("../bof/hello_bof.o");

fn main() {
    println!("Hello from bof_runner, feel free to run your BOFS!");

    let mut bof_handle: BofObjectHandle = BofObjectHandle { bits: 0 };
    let mut bof_context: *mut c_void = null_mut();
    unsafe {
        let result = bofObjectInitFromMemory(
            BOF_OBJECT.as_ptr(),
            BOF_OBJECT.len() as i32,
            &mut bof_handle
        );
        dbg!(result);

    }

    dbg!(bof_handle.clone());

    unsafe {
        let _ = bofObjectRun(
            bof_handle,
            null_mut(),
            0,
            &mut bof_context
        );
    }

}
