use std::fs::File;
use std::io::{self, Write};

use crate::Args;
use crate::block::EncryptedBlockDevice;
use crate::fs::encryptedfs::EncryptedFilesystem;

fn prompt_password() -> anyhow::Result<String> {
    print!("Enter password: ");
    io::stdout().flush()?;
    let password = rpassword::read_password()?;
    Ok(password)
}

fn prompt_new_passwords() -> anyhow::Result<(String, Option<String>)> {
    print!("Enter password for first half: ");
    io::stdout().flush()?;
    let password1 = rpassword::read_password()?;

    print!("Enter password for second half (or leave empty for undecypherable second half): ");
    io::stdout().flush()?;
    let password2 = rpassword::read_password()?;

    if password2.is_empty() {
        println!("Using an undecypherable second half.");
        Ok((password1, None))
    } else {
        Ok((password1, Some(password2)))
    }
}

#[inline]
pub fn svc_start(args: Args) -> anyhow::Result<EncryptedFilesystem> {
    let mountpoint = args.mountpoint.unwrap_or_else(|| "S:".into());

    let backing_file = args.backing_file.unwrap_or_else(|| {
        std::env::home_dir()
            .expect("Failed to locate home dir")
            .join("Secrets.shrodinger")
    });

    // Check if backing file exists to determine password prompt behavior
    if !backing_file.exists() {
        let file = File::create_new(&backing_file)?;
        let (password1, password2) = prompt_new_passwords()?;
        EncryptedBlockDevice::create(file, Some(&password1), password2.as_deref())?;
    }

    // Prompt for password
    println!("Opening encrypted volume...");
    let password = prompt_password()?;

    let mut encryptedfs = EncryptedFilesystem::create(
        &backing_file,
        &args.volume_prefix.unwrap_or_else(|| String::from("")),
        &password,
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
