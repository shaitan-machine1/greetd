use std::ffi::CString;

/// Overwrite secret buffers before releasing their storage.
pub trait Scrambler {
    fn scramble(&mut self);
}
fn overwrite(bytes: &mut [u8]) {
    for byte in bytes {
        unsafe {
            std::ptr::write_volatile(byte, 0);
        }
    }
}
impl Scrambler for Vec<u8> {
    fn scramble(&mut self) {
        self.resize(self.capacity(), 0);
        overwrite(self);
        self.clear();
    }
}
impl Scrambler for String {
    fn scramble(&mut self) {
        unsafe {
            let bytes = self.as_mut_vec();
            overwrite(bytes);
            bytes.clear();
        }
    }
}
impl Scrambler for CString {
    fn scramble(&mut self) {
        let mut bytes = std::mem::take(self).into_bytes_with_nul();
        overwrite(&mut bytes);
    }
}
