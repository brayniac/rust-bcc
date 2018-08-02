pub use self::inner::*;

#[cfg(feature="0.4.0")]
mod inner {
    use failure::Error;
    use bccapi::*;
    use bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
    use bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;

    use core::make_alphanumeric;
    use types::MutPointer;

    use std::ffi::CString;
    use std::fs::File;
    use std::hash::{Hash, Hasher};
    use std::os::unix::prelude::*;
    use std::ptr;

    #[derive(Debug)]
    pub struct Kprobe {
        code_fd: File,
        name: CString,
        p: MutPointer,
    }

    impl Kprobe {
        fn new(name: &str, attach_type: u32, function: &str, file: File) -> Result<Self, Error> {
            let name = CString::new(name).map_err(|_| {
                format_err!("Nul byte in Kprobe name: {}", name)
            })?;
            let function = CString::new(function).map_err(|_| {
                format_err!("Nul byte in Kprobe function: {}", function)
            })?;
            let (pid, cpu, group_fd) = (-1, 0, -1);
            let ptr = unsafe {
                bpf_attach_kprobe(
                    code.as_raw_fd(),
                    attach_type,
                    name.as_ptr(),
                    function.as_ptr(),
                    pid,
                    cpu,
                    group_fd,
                    None,
                    ptr::null_mut(),
                )
            };
            if ptr.is_null() {
                Err(format_err!("Failed to attach Kprobe: {:?}", name))
            } else {
                Ok(Self {
                    inner: ptr,
                    name: cname,
                    file,
                })
            }
        }

        pub fn attach_kprobe(function: &str, code: File) -> Result<Self, Error> {
            let name = format!("p_{}", &make_alphanumeric(function));
            Kprobe::new(&name, BPF_PROBE_ENTRY, function, code)
                .map_err(|_| format_err!("Failed to attach Kprobe: {}", name))
        }

        pub fn attach_kretprobe(function: &str, code: File) -> Result<Self, Error> {
            let name = format!("r_{}", &make_alphanumeric(function));
            Kprobe::new(&name, BPF_PROBE_RETURN, function, code)
                .map_err(|_| format_err!("Failed to attach Kretprobe: {}", name))
        }
    }

    impl Drop for Kprobe {
        fn drop(&mut self) {
            unsafe {
                bpf_detach_kprobe(self.name.as_ptr());
            }
        }
    }

    impl Eq for Kprobe {}

    impl Hash for Kprobe {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.name.hash(state);
        }
    }

    impl PartialEq for Kprobe {
        fn eq(&self, other: &Self) -> bool {
            self.name == other.name
        }
    }
}

#[cfg(feature="0.6.0")]
mod inner {
    use failure::Error;
    use bccapi::*;
    use bccapi::bpf_probe_attach_type_BPF_PROBE_ENTRY as BPF_PROBE_ENTRY;
    use bccapi::bpf_probe_attach_type_BPF_PROBE_RETURN as BPF_PROBE_RETURN;

    use core::make_alphanumeric;

    use std::ffi::CString;
    use std::fs::File;
    use std::hash::{Hash, Hasher};
    use std::os::unix::prelude::*;

    #[derive(Debug)]
    pub struct Kprobe {
        file: File,
        name: CString,
        inner: File,
    }

    impl Kprobe {
        fn new(name: &str, attach_type: u32, function: &str, file: File) -> Result<Self, Error> {
            let name = CString::new(name).map_err(|_| {
                format_err!("Nul byte in Kprobe name: {}", name)
            })?;
            let function = CString::new(function).map_err(|_| {
                format_err!("Nul byte in Kprobe function: {}", function)
            })?;
            let fd = unsafe {
                bpf_attach_kprobe(
                    file.as_raw_fd(),
                    attach_type,
                    name.as_ptr(),
                    function.as_ptr(),
                    0,
                )
            };
            if fd == -1 {
                Err(format_err!("Failed to attach Kprobe: {:?}", name))
            } else {
                Ok(Self {
                    inner: unsafe { File::from_raw_fd(fd) },
                    name,
                    file,
                })
            }
        }

        pub fn attach_kprobe(function: &str, code: File) -> Result<Self, Error> {
            let name = format!("p_{}", &make_alphanumeric(function));
            Kprobe::new(&name, BPF_PROBE_ENTRY, function, code)
                .map_err(|_| format_err!("Failed to attach Kprobe: {}", name))
        }

        pub fn attach_kretprobe(function: &str, code: File) -> Result<Self, Error> {
            let name = format!("r_{}", &make_alphanumeric(function));
            Kprobe::new(&name, BPF_PROBE_RETURN, function, code)
                .map_err(|_| format_err!("Failed to attach Kretprobe: {}", name))
        }
    }

    impl Drop for Kprobe {
        fn drop(&mut self) {
            unsafe {
                bpf_detach_kprobe(self.name.as_ptr());
            }
        }
    }

    impl Eq for Kprobe {}

    impl Hash for Kprobe {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.name.hash(state);
        }
    }

    impl PartialEq for Kprobe {
        fn eq(&self, other: &Self) -> bool {
            self.name == other.name
        }
    }
}