use crate::fs::context::EncryptedContext;
use std::fs::OpenOptions;

use std::path::Path;
use winfsp::host::{DebugMode, FileSystemHost, FileSystemParams, VolumeParams};

/// An passthrough filesystem using the NT API.
pub struct EncryptedFilesystem {
    /// The host for this filesystem.
    pub fs: FileSystemHost<EncryptedContext>,
}

impl EncryptedFilesystem {
    pub fn create(path: &Path, volume_prefix: &str, password: &str) -> anyhow::Result<Self> {
        let backing_file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(path)?;

        let mut volume_params = VolumeParams::new();
        volume_params
            .prefix(volume_prefix)
            .filesystem_name("encryptedfs");

        let context =
            EncryptedContext::new_with_volume_params(backing_file, password, &mut volume_params)?;

        volume_params.file_info_timeout(1000);
        Ok(EncryptedFilesystem {
            fs: FileSystemHost::new_with_options(
                FileSystemParams::default_params_debug(volume_params, DebugMode::all()),
                context,
            )?,
        })
    }
}
