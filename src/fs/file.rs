use winfsp::filesystem::DirBuffer;

/// A file context in the passthrough file system.
#[derive(Debug)]
pub struct EncryptedFile {
    is_directory: bool,
    dir_buffer: DirBuffer,
}

impl EncryptedFile {
    pub fn new(is_directory: bool) -> Self {
        Self {
            is_directory,
            dir_buffer: DirBuffer::new(),
        }
    }

    /// Whether or not this entry is a directory.
    pub fn is_directory(&self) -> bool {
        self.is_directory
    }

    /// Explicitly invalidate the handle before drop.
    pub fn close(self) {
        drop(self)
    }

    /// Get the directory buffer for this file.
    pub fn dir_buffer(&self) -> &DirBuffer {
        &self.dir_buffer
    }
}
