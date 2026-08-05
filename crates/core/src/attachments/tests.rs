//! Attachment handling.
//!
//! Almost everything here is about one attack: uploading a file that a browser
//! will execute as script, and sending a colleague the link so it runs against
//! their session on our origin. The defences are that the type comes from the
//! bytes rather than the uploader, that only formats which cannot carry script
//! render in place, and that a filename can never break out of the header it
//! is quoted in.

use super::*;

// ---------------------------------------------------------------------------
// What a file actually is
// ---------------------------------------------------------------------------

#[test]
fn types_come_from_the_bytes() {
    assert_eq!(sniff(b"\x89PNG\r\n\x1a\n rest").content_type, "image/png");
    assert_eq!(sniff(b"\xff\xd8\xff\xe0 rest").content_type, "image/jpeg");
    assert_eq!(sniff(b"GIF89a rest").content_type, "image/gif");
    assert_eq!(sniff(b"%PDF-1.7 rest").content_type, "application/pdf");

    let mut webp = b"RIFF\x00\x00\x00\x00WEBP".to_vec();
    webp.extend_from_slice(b"rest");
    assert_eq!(sniff(&webp).content_type, "image/webp");
}

/// **The attack.** A file named `photo.png` whose contents are HTML must not
/// be served as an image, and must never render in place.
#[test]
fn a_html_file_wearing_a_png_name_is_not_an_image() {
    let hostile = b"<html><script>fetch('/api/oneroster/v1p1/users')</script>";
    let kind = sniff(hostile);
    assert_eq!(kind.content_type, "application/octet-stream");
    assert!(!kind.inline, "it must be downloaded, never rendered");
}

/// SVG is an image to a person and a scriptable document to a browser. It is
/// left unrecognised on purpose, so it downloads rather than renders.
#[test]
fn svg_is_not_treated_as_a_renderable_image() {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>"#;
    let kind = sniff(svg);
    assert!(!kind.inline);
    assert_ne!(kind.content_type, "image/svg+xml");
}

/// Only formats that cannot carry script may render in place.
#[test]
fn nothing_scriptable_is_ever_inline() {
    for bytes in [
        b"\x89PNG\r\n\x1a\n".as_slice(),
        b"\xff\xd8\xff".as_slice(),
        b"GIF89a".as_slice(),
    ] {
        assert!(sniff(bytes).inline, "images are worth rendering");
    }
    assert!(
        !sniff(b"%PDF-1.7").inline,
        "a PDF has script and an embedded viewer — download it"
    );
    assert!(!sniff(b"anything else").inline);
}

#[test]
fn a_truncated_file_does_not_panic_or_guess() {
    for bytes in [b"".as_slice(), b"\x89".as_slice(), b"RIFF".as_slice()] {
        assert_eq!(sniff(bytes).content_type, "application/octet-stream");
    }
}

// ---------------------------------------------------------------------------
// Filenames
// ---------------------------------------------------------------------------

#[test]
fn a_filename_cannot_carry_a_path() {
    assert_eq!(safe_filename("../../etc/passwd"), "passwd");
    assert_eq!(safe_filename("C:\\Windows\\system32\\cmd.exe"), "cmd.exe");
    assert_eq!(safe_filename("/absolute/photo.png"), "photo.png");
}

/// A leading dot would make the stored name a hidden file and, worse, `..` is
/// a path component wearing a filename.
#[test]
fn a_filename_cannot_be_dots() {
    assert_eq!(safe_filename(".."), "attachment");
    assert_eq!(safe_filename("."), "attachment");
    assert_eq!(safe_filename(".hidden"), "hidden");
}

/// A quote would end the quoted string in `Content-Disposition` early and let
/// the rest of the name become header syntax.
#[test]
fn a_filename_cannot_break_out_of_a_header() {
    let hostile = "evil\";\r\nSet-Cookie: admin=1;\"x.png";
    let safe = safe_filename(hostile);
    assert!(!safe.contains('"'));
    assert!(!safe.contains('\r'));
    assert!(!safe.contains('\n'));

    let header = content_disposition(hostile, false);
    assert_eq!(header.matches('"').count(), 2, "exactly one quoted string");
    assert!(!header.contains("Set-Cookie: admin=1;\""));
}

#[test]
fn an_empty_or_absurd_filename_still_produces_something() {
    assert_eq!(safe_filename(""), "attachment");
    assert_eq!(safe_filename("   "), "attachment");
    assert_eq!(safe_filename(&"a".repeat(500)).len(), 120);
}

#[test]
fn a_non_ascii_filename_survives_as_well_as_being_safe() {
    let header = content_disposition("Bildschirm kaputt — Foto.png", false);
    assert!(header.starts_with("attachment; filename=\""));
    assert!(
        header.contains("filename*=UTF-8''"),
        "the real name is preserved for clients that can read it: {header}"
    );
}

#[test]
fn inline_and_attachment_are_stated_explicitly() {
    assert!(content_disposition("a.png", true).starts_with("inline;"));
    assert!(content_disposition("a.bin", false).starts_with("attachment;"));
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

#[test]
fn limits_are_enforced_and_explained() {
    assert_eq!(check(b"", 0), Err(UploadError::Empty));
    assert_eq!(
        check(&vec![0u8; MAX_ATTACHMENT_BYTES + 1], 0),
        Err(UploadError::TooLarge)
    );
    assert_eq!(
        check(b"ok", MAX_ATTACHMENTS_PER_MESSAGE),
        Err(UploadError::TooMany)
    );
    assert_eq!(check(b"ok", MAX_ATTACHMENTS_PER_MESSAGE - 1), Ok(()));
    assert_eq!(check(&vec![0u8; MAX_ATTACHMENT_BYTES], 0), Ok(()));
}

#[test]
fn every_refusal_tells_the_person_what_to_do() {
    for e in [
        UploadError::Empty,
        UploadError::TooLarge,
        UploadError::TooMany,
    ] {
        let m = e.message();
        assert!(m.ends_with('.'), "{m:?}");
        assert!(!m.to_lowercase().contains("invalid"), "{m:?}");
    }
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

#[tokio::test]
async fn a_file_comes_back_exactly_as_it_went_in() {
    let dir = tempfile::tempdir().unwrap();
    let store = FsAttachmentStore::new(dir.path());
    let bytes = b"\x89PNG\r\n\x1a\n some pixels".to_vec();

    let key = store
        .put("abcdef01-2345-6789-abcd-ef0123456789", &bytes)
        .await
        .unwrap();
    assert_eq!(store.get(&key).await.unwrap(), bytes);
    assert_eq!(digest(&store.get(&key).await.unwrap()), digest(&bytes));
}

/// Sharded, so a district with fifty thousand attachments does not get one
/// directory that takes a second to list.
#[tokio::test]
async fn keys_are_sharded_by_prefix() {
    let dir = tempfile::tempdir().unwrap();
    let store = FsAttachmentStore::new(dir.path());
    let key = store.put("abcdef01-2345", b"x").await.unwrap();
    assert_eq!(key, "ab/abcdef01-2345");
    assert!(dir.path().join("ab").join("abcdef01-2345").exists());
}

/// **The traversal test.** Keys come from our own database, but a database is
/// not a trust boundary worth betting on: a bad restore that put `../../` in
/// the column must not be able to read it back.
#[tokio::test]
async fn a_malformed_key_cannot_escape_the_store() {
    let dir = tempfile::tempdir().unwrap();
    let secret = dir.path().parent().unwrap().join("secret.txt");
    tokio::fs::write(&secret, b"not yours").await.unwrap();

    let store = FsAttachmentStore::new(dir.path());
    for key in [
        "../secret.txt",
        "ab/../../secret.txt",
        "../../etc/passwd",
        "ab/sub/dir",
        "/etc/passwd",
        "ab/",
        "",
        "abc/name",
    ] {
        assert!(
            store.get(key).await.is_err(),
            "key {key:?} was allowed to resolve"
        );
    }
}

#[tokio::test]
async fn deleting_something_already_gone_is_success() {
    let dir = tempfile::tempdir().unwrap();
    let store = FsAttachmentStore::new(dir.path());
    let key = store.put("abcdef01", b"x").await.unwrap();
    store.delete(&key).await.unwrap();
    store
        .delete(&key)
        .await
        .expect("already deleted is the state we wanted");
    assert!(store.get(&key).await.is_err());
}

#[test]
fn the_digest_is_the_usual_sha256() {
    // Well-known value, so a change of algorithm is loud rather than silent.
    assert_eq!(
        digest(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}
