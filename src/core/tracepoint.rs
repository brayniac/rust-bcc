pub use self::inner::*;

#[cfg(feature="0.4.0")]
mod inner {

    use failure::Error;
    use bccapi::*;

    use types::MutPointer;

    use std::ffi::CString;
    use std::fs::File;
    use std::hash::{Hash, Hasher};
    use std::os::unix::prelude::*;
    use std::ptr;

    #[derive(Debug)]
    pub struct Tracepoint {
        category: CString,
        name: CString,
        file: File,
        inner: MutPointer,
    }

    impl Tracepoint {
        pub fn attach_tracepoint(
            category: &str,
            name: &str,
            file: File,
        ) -> Result<Self, Error> {
            let name = CString::new(name).map_err(|_| {
                format_err!("Nul byte in Tracepoint name: {}", name)
            })?;
            let category = CString::new(subsys).map_err(|_| {
                format_err!("Nul byte in Tracepoint subsys: {}", subsys)
            })?;
            // NOTE: BPF events are system-wide and do not support CPU filter
            let (pid, cpu, group_fd) = (-1, 0, -1);
            let inner = unsafe {
                bpf_attach_tracepoint(
                    file.as_raw_fd(),
                    category.as_ptr(),
                    name.as_ptr(),
                    pid,
                    cpu,
                    group_fd,
                    None,
                    ptr::null_mut(),
                )
            };
            if inner.is_null() {
                return Err(format_err!("Failed to attach tracepoint: {:?}:{:?}", category, name));
            } else {
                Ok(Self{
                    category,
                    name,
                    file,
                    inner,
                })
            }
        }
    }

    impl PartialEq for Tracepoint {
        fn eq(&self, other: &Tracepoint) -> bool {
            self.subsys == other.subsys && self.name == other.name
        }
    }

    impl Eq for Tracepoint {}

    impl Hash for Tracepoint {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.subsys.hash(state);
            self.name.hash(state);
        }
    }

    impl Drop for Tracepoint {
        fn drop(&mut self) {
            unsafe {
                bpf_detach_tracepoint(self.subsys.as_ptr(), self.name.as_ptr());
            }
        }
    }
}

#[cfg(feature="0.6.0")]
mod inner {
    use failure::Error;
    use bccapi::*;

    use std::ffi::CString;
    use std::fs::File;
    use std::hash::{Hash, Hasher};
    use std::os::unix::prelude::*;

    #[derive(Debug)]
    pub struct Tracepoint {
        category: CString,
        name: CString,
        file: File,
        inner: File,
    }

    impl Tracepoint {
        pub fn attach_tracepoint(
            category: &str,
            name: &str,
            file: File,
        ) -> Result<Self, Error> {
            let name = CString::new(name).map_err(|_| {
                format_err!("Nul byte in Tracepoint name: {}", name)
            })?;
            let category = CString::new(category).map_err(|_| {
                format_err!("Nul byte in Tracepoint category: {}", category)
            })?;
            let fd = unsafe {
                bpf_attach_tracepoint(
                    file.as_raw_fd(),
                    category.as_ptr(),
                    name.as_ptr(),
                )
            };
            if fd == -1 {
                return Err(format_err!("Failed to attach tracepoint: {:?}:{:?}", category, name));
            } else {
                Ok(Self{
                    category,
                    name,
                    file,
                    inner: unsafe { File::from_raw_fd(fd) },
                })
            }
        }
    }

    impl PartialEq for Tracepoint {
        fn eq(&self, other: &Tracepoint) -> bool {
            self.category == other.category && self.name == other.name
        }
    }

    impl Eq for Tracepoint {}

    impl Hash for Tracepoint {
        fn hash<H: Hasher>(&self, state: &mut H) {
            self.category.hash(state);
            self.name.hash(state);
        }
    }

    impl Drop for Tracepoint {
        fn drop(&mut self) {
            unsafe {
                bpf_detach_tracepoint(self.category.as_ptr(), self.name.as_ptr());
            }
        }
    }
}