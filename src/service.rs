use std::fs;

use crate::Args;
use crate::fs::encryptedfs::EncryptedFilesystem;

#[inline]
pub fn svc_start(args: Args) -> anyhow::Result<EncryptedFilesystem> {
    let mountpoint = args.mountpoint.unwrap_or_else(|| {
        std::env::home_dir()
            .expect("Failed to locate home dir")
            .join("Secrets")
    });
    // fs::create_dir_all(&mountpoint)?;

    let mut encryptedfs = EncryptedFilesystem::create(
        &args.backing_file.unwrap_or_else(|| {
            std::env::home_dir()
                .expect("Failed to locate home dir")
                .join("Secrets.shrodinger")
        }),
        &args.volume_prefix.unwrap_or_else(|| String::from("")),
    )?;
    encryptedfs.fs.mount(&mountpoint)?;
    encryptedfs.fs.start()?;
    Ok(encryptedfs)
}

#[inline]
pub fn svc_stop(fs: Option<&mut EncryptedFilesystem>) {
    if let Some(f) = fs {
        f.fs.stop();
    }
}
