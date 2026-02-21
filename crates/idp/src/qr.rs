//! QR code generation and badge token utilities.

use chalk_core::error::{ChalkError, Result};
use image::Luma;
use qrcode::QrCode;
use uuid::Uuid;

/// Generate a QR code PNG image from the given data string.
pub fn generate_qr_png(data: &str) -> Result<Vec<u8>> {
    let code = QrCode::new(data.as_bytes())
        .map_err(|e| ChalkError::Idp(format!("failed to create QR code: {e}")))?;

    let image = code.render::<Luma<u8>>().build();
    let mut png_bytes: Vec<u8> = Vec::new();
    let encoder = image::codecs::png::PngEncoder::new(&mut png_bytes);
    image::ImageEncoder::write_image(
        encoder,
        image.as_raw(),
        image.width(),
        image.height(),
        image::ExtendedColorType::L8,
    )
    .map_err(|e| ChalkError::Idp(format!("failed to encode QR code PNG: {e}")))?;

    Ok(png_bytes)
}

/// Generate a unique badge token using UUID v4.
pub fn generate_badge_token() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_valid_png_bytes() {
        let png = generate_qr_png("https://chalk.example.com/badge/test-token").unwrap();
        // PNG magic bytes
        assert!(png.len() > 8);
        assert_eq!(&png[..4], &[0x89, b'P', b'N', b'G']);
    }

    #[test]
    fn generates_png_for_short_data() {
        let png = generate_qr_png("hello").unwrap();
        assert!(!png.is_empty());
        assert_eq!(&png[..4], &[0x89, b'P', b'N', b'G']);
    }

    #[test]
    fn badge_token_is_unique() {
        let token1 = generate_badge_token();
        let token2 = generate_badge_token();
        assert_ne!(token1, token2);
    }

    #[test]
    fn badge_token_is_valid_uuid() {
        let token = generate_badge_token();
        assert!(Uuid::parse_str(&token).is_ok());
    }

    #[test]
    fn badge_token_has_correct_format() {
        let token = generate_badge_token();
        // UUID v4 format: 8-4-4-4-12 hex characters
        assert_eq!(token.len(), 36);
        assert_eq!(token.chars().filter(|&c| c == '-').count(), 4);
    }
}
