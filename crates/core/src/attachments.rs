//! Storing what a requester sends with a ticket.
//!
//! # Why a photo matters
//!
//! "The screen is broken" and a photograph of the screen are not the same
//! request. The photograph tells a technician whether it is the panel or the
//! digitiser, whether the case is cracked, and whether it is an insurance
//! claim — before anyone walks to the classroom. It is the single most useful
//! thing a teacher can send, and it is the reason this exists at all.
//!
//! # Trusting nothing the browser says
//!
//! The declared filename and content type come from whoever is uploading, so
//! neither is used to decide anything. The type is determined from the leading
//! bytes of the file; the storage key is derived from a UUID we generate; and
//! the filename is kept only to show the person what they sent. A file whose
//! contents do not match a type we recognise is stored as
//! `application/octet-stream` and can only ever be downloaded, never rendered.
//!
//! That is the whole defence against the obvious attack: uploading an HTML or
//! SVG file to a ticket and sending a colleague the link, so it runs as
//! same-origin script against their session.

use std::path::{Path, PathBuf};

use async_trait::async_trait;
use sha2::{Digest, Sha256};

use crate::error::{ChalkError, Result};

/// The largest file a requester may attach.
///
/// Below the multipart body limit the console enforces, because the body also
/// carries the form fields. A phone photo is 2–5 MB, which is the case this
/// number exists to serve.
pub const MAX_ATTACHMENT_BYTES: usize = 6 * 1024 * 1024;

/// How many files may ride along with one message.
pub const MAX_ATTACHMENTS_PER_MESSAGE: usize = 5;

/// A content type we are willing to identify, and whether a browser may render
/// it in place.
///
/// Inline rendering is the difference between a technician seeing the cracked
/// screen and downloading a file to look at it, so it is worth having — but
/// only for formats that cannot carry script. **SVG is deliberately absent**:
/// it is an image to a person and a document with `<script>` to a browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Kind {
    pub content_type: &'static str,
    pub inline: bool,
}

const OCTET_STREAM: Kind = Kind {
    content_type: "application/octet-stream",
    inline: false,
};

/// Identify a file from its leading bytes.
///
/// Never from its name or its declared type: both are supplied by the
/// uploader, and a `.png` containing HTML is the entire attack.
pub fn sniff(bytes: &[u8]) -> Kind {
    const SIGNATURES: &[(&[u8], &str, bool)] = &[
        (b"\x89PNG\r\n\x1a\n", "image/png", true),
        (b"\xff\xd8\xff", "image/jpeg", true),
        (b"GIF87a", "image/gif", true),
        (b"GIF89a", "image/gif", true),
        (b"%PDF-", "application/pdf", false),
    ];

    for (magic, content_type, inline) in SIGNATURES {
        if bytes.starts_with(magic) {
            return Kind {
                content_type,
                inline: *inline,
            };
        }
    }
    // WEBP is RIFF....WEBP — the tag is at offset 8, so it needs its own check.
    if bytes.len() >= 12 && bytes.starts_with(b"RIFF") && &bytes[8..12] == b"WEBP" {
        return Kind {
            content_type: "image/webp",
            inline: true,
        };
    }
    OCTET_STREAM
}

/// Reduce a browser-supplied filename to something safe to store and to echo
/// back in a `Content-Disposition` header.
///
/// Directory components are dropped rather than escaped — a name containing a
/// path is either an accident or an attempt, and neither deserves the original
/// back. Quotes and control characters go because they would let a filename
/// break out of the header it is quoted in.
pub fn safe_filename(raw: &str) -> String {
    let base = raw
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('.');

    let cleaned: String = base
        .chars()
        .filter(|c| !c.is_control() && !matches!(c, '"' | '\\' | '\r' | '\n'))
        .take(120)
        .collect();

    if cleaned.is_empty() {
        "attachment".to_string()
    } else {
        cleaned
    }
}

/// Where attachment bytes live.
///
/// A trait because hosted will put them in object storage while self-host
/// keeps them on disk, and neither the handlers nor the repository should
/// know which. The `key` is opaque and produced by [`AttachmentStore::put`].
#[async_trait]
pub trait AttachmentStore: Send + Sync {
    /// Store `bytes` and return the key needed to read them back.
    async fn put(&self, id: &str, bytes: &[u8]) -> Result<String>;
    async fn get(&self, key: &str) -> Result<Vec<u8>>;
    async fn delete(&self, key: &str) -> Result<()>;
}

/// Attachments on the local filesystem.
///
/// Keys are `ab/<uuid>` — sharded by the first two characters so a district
/// with fifty thousand attachments does not end up with a directory that takes
/// a second to list.
pub struct FsAttachmentStore {
    root: PathBuf,
}

impl FsAttachmentStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve a key to a path, refusing anything that is not the shape we
    /// write.
    ///
    /// Keys come from our own database, but a database is not a trust boundary
    /// worth betting a path traversal on: a bug or a bad restore that put
    /// `../../etc/passwd` in the column must not be able to read it back.
    fn path_for(&self, key: &str) -> Result<PathBuf> {
        let mut parts = key.split('/');
        let (Some(shard), Some(name), None) = (parts.next(), parts.next(), parts.next()) else {
            return Err(ChalkError::Validation(format!(
                "malformed attachment key: {key}"
            )));
        };
        let ok =
            |s: &str| !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-');
        if shard.len() != 2 || !ok(shard) || !ok(name) {
            return Err(ChalkError::Validation(format!(
                "malformed attachment key: {key}"
            )));
        }
        Ok(self.root.join(shard).join(name))
    }
}

#[async_trait]
impl AttachmentStore for FsAttachmentStore {
    async fn put(&self, id: &str, bytes: &[u8]) -> Result<String> {
        let shard: String = id.chars().take(2).collect();
        let key = format!("{shard}/{id}");
        let path = self.path_for(&key)?;
        if let Some(dir) = path.parent() {
            tokio::fs::create_dir_all(dir).await?;
        }
        tokio::fs::write(&path, bytes).await?;
        Ok(key)
    }

    async fn get(&self, key: &str) -> Result<Vec<u8>> {
        let path = self.path_for(key)?;
        Ok(tokio::fs::read(&path).await?)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = self.path_for(key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            // Already gone is the state we wanted.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

/// Hex SHA-256 of the stored bytes, so a restore can prove it got back what it
/// put in.
pub fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Why an upload was refused, in words a form can show.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UploadError {
    Empty,
    TooLarge,
    TooMany,
}

impl UploadError {
    pub fn message(&self) -> String {
        match self {
            Self::Empty => "That file was empty.".into(),
            Self::TooLarge => format!(
                "Files need to be under {} MB. Try a photo instead of a video.",
                MAX_ATTACHMENT_BYTES / (1024 * 1024)
            ),
            Self::TooMany => {
                format!("You can attach up to {MAX_ATTACHMENTS_PER_MESSAGE} files at a time.")
            }
        }
    }
}

/// Check one file before it is stored.
pub fn check(bytes: &[u8], already_attached: usize) -> std::result::Result<(), UploadError> {
    if bytes.is_empty() {
        return Err(UploadError::Empty);
    }
    if bytes.len() > MAX_ATTACHMENT_BYTES {
        return Err(UploadError::TooLarge);
    }
    if already_attached >= MAX_ATTACHMENTS_PER_MESSAGE {
        return Err(UploadError::TooMany);
    }
    Ok(())
}

/// A `Content-Disposition` value that cannot break out of its own header.
///
/// The filename is quoted, and `safe_filename` has already removed the
/// characters that would end the quoting early. Non-ASCII names additionally
/// get the RFC 5987 form so they survive intact rather than being mangled.
pub fn content_disposition(filename: &str, inline: bool) -> String {
    let disposition = if inline { "inline" } else { "attachment" };
    let safe = safe_filename(filename);
    let ascii: String = safe
        .chars()
        .map(|c| {
            if c.is_ascii_graphic() || c == ' ' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if ascii == safe {
        format!("{disposition}; filename=\"{ascii}\"")
    } else {
        format!(
            "{disposition}; filename=\"{ascii}\"; filename*=UTF-8''{}",
            urlencoding::encode(&safe)
        )
    }
}

/// Where on disk attachments go by default, under the configured data dir.
pub fn default_root(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("attachments")
}

#[cfg(test)]
mod tests;
