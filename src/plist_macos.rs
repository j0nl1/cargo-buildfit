//! Decode installed property lists through the native, format-aware parser.
use anyhow::{Result, bail};
use std::ffi::{c_char, c_void};
type Object = *const c_void;
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFDataCreate(allocator: Object, bytes: *const u8, length: isize) -> Object;
    fn CFPropertyListCreateWithData(
        allocator: Object,
        data: Object,
        options: usize,
        format: *mut isize,
        error: *mut Object,
    ) -> Object;
    fn CFRelease(object: Object);
    fn CFGetTypeID(object: Object) -> usize;
    fn CFStringGetTypeID() -> usize;
    fn CFArrayGetTypeID() -> usize;
    fn CFDictionaryGetTypeID() -> usize;
    fn CFStringGetLength(string: Object) -> isize;
    fn CFStringGetMaximumSizeForEncoding(length: isize, encoding: u32) -> isize;
    fn CFStringGetCString(string: Object, buffer: *mut c_char, size: isize, encoding: u32) -> u8;
    fn CFArrayGetCount(array: Object) -> isize;
    fn CFArrayGetValueAtIndex(array: Object, index: isize) -> Object;
    fn CFDictionaryGetCount(dictionary: Object) -> isize;
    fn CFDictionaryGetKeysAndValues(dictionary: Object, keys: *mut Object, values: *mut Object);
}
struct Owned(Object);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { CFRelease(self.0) }
        }
    }
}
pub fn strings(bytes: &[u8]) -> Result<Vec<u8>> {
    let data =
        Owned(unsafe { CFDataCreate(std::ptr::null(), bytes.as_ptr(), bytes.len() as isize) });
    if data.0.is_null() {
        bail!("property list allocation unavailable");
    }
    let value = unsafe {
        CFPropertyListCreateWithData(
            std::ptr::null(),
            data.0,
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if value.is_null() {
        bail!("installed property list decoding failed");
    }
    let value = Owned(value);
    let mut output = Vec::new();
    collect(value.0, &mut output, &mut 100_000, 0)?;
    Ok(output)
}
fn collect(value: Object, output: &mut Vec<u8>, budget: &mut usize, depth: usize) -> Result<()> {
    if value.is_null() || *budget == 0 || depth > 128 {
        bail!("property list scan limit reached");
    }
    *budget -= 1;
    unsafe {
        let kind = CFGetTypeID(value);
        if kind == CFStringGetTypeID() {
            let capacity = CFStringGetMaximumSizeForEncoding(CFStringGetLength(value), 0x08000100);
            if !(0..=16 * 1024 * 1024).contains(&capacity) {
                bail!("property list string limit reached");
            }
            let mut bytes = vec![0u8; capacity as usize + 1];
            if CFStringGetCString(
                value,
                bytes.as_mut_ptr().cast(),
                bytes.len() as isize,
                0x08000100,
            ) == 0
            {
                bail!("property list string decoding failed");
            }
            let length = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
            if output.len().saturating_add(length + 1) > 16 * 1024 * 1024 {
                bail!("property list output limit reached");
            }
            output.extend_from_slice(&bytes[..length]);
            output.push(b'\n');
        } else if kind == CFArrayGetTypeID() {
            let count = CFArrayGetCount(value);
            if count < 0 || count as usize > *budget {
                bail!("property list array limit reached");
            }
            for i in 0..count {
                collect(CFArrayGetValueAtIndex(value, i), output, budget, depth + 1)?;
            }
        } else if kind == CFDictionaryGetTypeID() {
            let count = CFDictionaryGetCount(value);
            if count < 0 || count as usize > *budget {
                bail!("property list dictionary limit reached");
            }
            let mut values = vec![std::ptr::null(); count as usize];
            CFDictionaryGetKeysAndValues(value, std::ptr::null_mut(), values.as_mut_ptr());
            for v in values {
                collect(v, output, budget, depth + 1)?;
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_plist_decodes_escaped_paths_and_non_json_values() {
        let bytes=br#"<?xml version="1.0" encoding="UTF-8"?><plist version="1.0"><dict><key>ProgramArguments</key><array><string>/a &amp; b/target/test</string></array><key>date</key><date>2026-11-05T00:00:00Z</date></dict></plist>"#;
        assert_eq!(strings(bytes).unwrap(), b"/a & b/target/test\n");
        assert!(strings(b"<plist><dict>").is_err());
    }
}
