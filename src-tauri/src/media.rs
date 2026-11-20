use base64::{engine::general_purpose::STANDARD, Engine};
use image::{
    codecs::jpeg::JpegEncoder,
    imageops::FilterType,
    ColorType, DynamicImage, GenericImageView, ImageReader,
};
use std::collections::HashMap;
use std::path::Path;

const ASCII_CHARS: &[u8] = b" .:-=+*#%@";
const ASCII_COLS: usize = 64;
const ASCII_ROWS: usize = 32;

pub struct ImageMetrics {
    pub path: String,
    pub width: u32,
    pub height: u32,
    pub mode: String,
    pub has_alpha: bool,
    pub mask_source: &'static str,
    pub coverage_pct: f64,
    pub bbox: Option<[u32; 4]>,
    pub semi_transparent_pct: f64,
    pub top_colors: Vec<(String, f64)>,
    pub ascii: String,
}

fn color_mode_label(ct: ColorType) -> (&'static str, bool) {
    match ct {
        ColorType::L8 | ColorType::L16 => ("L", false),
        ColorType::La8 | ColorType::La16 => ("LA", true),
        ColorType::Rgb8 | ColorType::Rgb16 | ColorType::Rgb32F => ("RGB", false),
        ColorType::Rgba8 | ColorType::Rgba16 | ColorType::Rgba32F => ("RGBA", true),
        _ => ("OTHER", false),
    }
}

pub fn analyze_image(path: &Path) -> Result<ImageMetrics, String> {
    let reader = ImageReader::open(path)
        .map_err(|e| format!("open image: {e}"))?
        .with_guessed_format()
        .map_err(|e| format!("detect format: {e}"))?;
    let im = reader.decode().map_err(|e| format!("decode image: {e}"))?;

    let (width, height) = im.dimensions();
    let (mode, has_alpha) = color_mode_label(im.color());
    let rgba = im.to_rgba8();
    let total = (width as usize) * (height as usize);

    let min_alpha = if has_alpha {
        rgba.pixels().map(|p| p[3]).min().unwrap_or(255)
    } else {
        255
    };

    let use_alpha_mask = has_alpha && min_alpha < 250;
    let mask_source = if use_alpha_mask { "alpha" } else { "background" };

    // Estimate background color from the four corners if no transparency exists.
    let bg = if !use_alpha_mask && width > 0 && height > 0 {
        let c = [
            rgba.get_pixel(0, 0).0,
            rgba.get_pixel(width - 1, 0).0,
            rgba.get_pixel(0, height - 1).0,
            rgba.get_pixel(width - 1, height - 1).0,
        ];
        let median_ch = |ch: usize| -> i16 {
            let mut vals = [c[0][ch], c[1][ch], c[2][ch], c[3][ch]];
            vals.sort_unstable();
            ((vals[1] as i16) + (vals[2] as i16)) / 2
        };
        [median_ch(0), median_ch(1), median_ch(2)]
    } else {
        [0, 0, 0]
    };

    let mut mask = vec![false; total];
    let mut covered: usize = 0;
    let mut semi: usize = 0;
    let mut min_x = u32::MAX;
    let mut min_y = u32::MAX;
    let mut max_x = 0u32;
    let mut max_y = 0u32;
    let mut hist: HashMap<u16, usize> = HashMap::new();

    for (idx, p) in rgba.pixels().enumerate() {
        let is_fg = if use_alpha_mask {
            p[3] > 8
        } else {
            let dr = (p[0] as i16 - bg[0]).abs();
            let dg = (p[1] as i16 - bg[1]).abs();
            let db = (p[2] as i16 - bg[2]).abs();
            dr.max(dg).max(db) > 16
        };
        if is_fg {
            mask[idx] = true;
            covered += 1;
            let x = (idx as u32) % width;
            let y = (idx as u32) / width;
            if x < min_x { min_x = x; }
            if y < min_y { min_y = y; }
            if x > max_x { max_x = x; }
            if y > max_y { max_y = y; }
            if has_alpha && p[3] > 8 && p[3] < 247 {
                semi += 1;
            }
            let key = (((p[0] >> 4) as u16) << 8)
                | (((p[1] >> 4) as u16) << 4)
                | ((p[2] >> 4) as u16);
            *hist.entry(key).or_insert(0) += 1;
        }
    }

    let coverage = if total > 0 {
        (covered as f64) / (total as f64)
    } else {
        0.0
    };
    let bbox = if covered > 0 {
        Some([min_x, min_y, max_x, max_y])
    } else {
        None
    };
    let semi_pct = if has_alpha && covered > 0 {
        ((semi as f64) / (covered as f64) * 1000.0).round() / 10.0
    } else {
        0.0
    };

    let mut pairs: Vec<(u16, usize)> = hist.into_iter().collect();
    pairs.sort_unstable_by(|a, b| b.1.cmp(&a.1));
    let top_colors: Vec<(String, f64)> = pairs
        .into_iter()
        .take(5)
        .map(|(k, count)| {
            let r = ((k >> 8) & 15) * 16 + 8;
            let g = ((k >> 4) & 15) * 16 + 8;
            let b = (k & 15) * 16 + 8;
            let pct = ((count as f64) / (covered.max(1) as f64) * 1000.0).round() / 10.0;
            (format!("#{r:02x}{g:02x}{b:02x}"), pct)
        })
        .collect();

    let ascii = build_ascii(&im, &mask, width, height, coverage > 0.97);

    Ok(ImageMetrics {
        path: path.to_string_lossy().to_string(),
        width,
        height,
        mode: mode.into(),
        has_alpha,
        mask_source,
        coverage_pct: (coverage * 1000.0).round() / 10.0,
        bbox,
        semi_transparent_pct: semi_pct,
        top_colors,
        ascii,
    })
}

fn build_ascii(im: &DynamicImage, mask: &[bool], w: u32, h: u32, use_luminance: bool) -> String {
    if w == 0 || h == 0 {
        return String::new();
    }
    let mut lines = Vec::with_capacity(ASCII_ROWS);
    if use_luminance {
        let gray = im
            .grayscale()
            .resize_exact(ASCII_COLS as u32, ASCII_ROWS as u32, FilterType::Triangle)
            .to_luma8();
        for y in 0..ASCII_ROWS {
            let mut row = String::with_capacity(ASCII_COLS);
            for x in 0..ASCII_COLS {
                let v = gray.get_pixel(x as u32, y as u32)[0] as f64;
                let idx = ((9.0 - (v / 255.0) * 9.0).round() as isize).clamp(0, 9) as usize;
                row.push(ASCII_CHARS[idx] as char);
            }
            lines.push(row);
        }
    } else {
        for ry in 0..ASCII_ROWS {
            let y0 = (ry * h as usize) / ASCII_ROWS;
            let y1 = (((ry + 1) * h as usize) / ASCII_ROWS).max(y0 + 1).min(h as usize);
            let mut row = String::with_capacity(ASCII_COLS);
            for rx in 0..ASCII_COLS {
                let x0 = (rx * w as usize) / ASCII_COLS;
                let x1 = (((rx + 1) * w as usize) / ASCII_COLS).max(x0 + 1).min(w as usize);
                let mut hits = 0usize;
                let mut cells = 0usize;
                for y in y0..y1 {
                    let base = y * (w as usize);
                    for x in x0..x1 {
                        if mask[base + x] {
                            hits += 1;
                        }
                        cells += 1;
                    }
                }
                let ratio = (hits as f64) / (cells.max(1) as f64);
                let idx = ((ratio * 9.0).round() as isize).clamp(0, 9) as usize;
                row.push(ASCII_CHARS[idx] as char);
            }
            lines.push(row);
        }
    }
    lines.join("\n")
}

pub struct Base64Preview {
    pub orig_width: u32,
    pub orig_height: u32,
    pub out_width: u32,
    pub out_height: u32,
    pub quality: u8,
    pub bytes_len: usize,
    pub base64_jpeg: String,
}

/// Native Rust image resizer + JPEG encoder capped to `max_kb` (so Gemini can decode & visually inspect it).
/// Composites transparent areas over neutral checkerboard/slate gray so alpha silhouettes remain visible.
pub fn encode_base64_preview(
    path: &Path,
    max_edge: u32,
    max_kb: usize,
) -> Result<Base64Preview, String> {
    let reader = ImageReader::open(path)
        .map_err(|e| format!("open image: {e}"))?
        .with_guessed_format()
        .map_err(|e| format!("detect format: {e}"))?;
    let im = reader.decode().map_err(|e| format!("decode image: {e}"))?;
    let (orig_width, orig_height) = im.dimensions();

    // Composite over dark slate (#1e2430) if image has alpha so transparent edges stay legible in JPEG.
    let rgba = im.to_rgba8();
    let mut rgb = image::RgbImage::new(orig_width, orig_height);
    for (x, y, p) in rgba.enumerate_pixels() {
        let a = p[3] as f32 / 255.0;
        let inv = 1.0 - a;
        let r = (p[0] as f32 * a + 30.0 * inv).round() as u8;
        let g = (p[1] as f32 * a + 36.0 * inv).round() as u8;
        let b = (p[2] as f32 * a + 48.0 * inv).round() as u8;
        rgb.put_pixel(x, y, image::Rgb([r, g, b]));
    }
    let dyn_rgb = DynamicImage::ImageRgb8(rgb);

    let max_bytes = max_kb.clamp(16, 180) * 1024;
    let mut edge = max_edge.clamp(256, 1600);

    for _scale_step in 0..4 {
        let resized = if orig_width > edge || orig_height > edge {
            dyn_rgb.resize(edge, edge, FilterType::Lanczos3)
        } else {
            dyn_rgb.clone()
        };
        let (out_width, out_height) = resized.dimensions();

        for &q in &[84u8, 72, 60, 48, 38] {
            let mut buf = Vec::new();
            let mut enc = JpegEncoder::new_with_quality(&mut buf, q);
            enc.encode_image(&resized)
                .map_err(|e| format!("jpeg encode: {e}"))?;
            if buf.len() <= max_bytes {
                return Ok(Base64Preview {
                    orig_width,
                    orig_height,
                    out_width,
                    out_height,
                    quality: q,
                    bytes_len: buf.len(),
                    base64_jpeg: STANDARD.encode(&buf),
                });
            }
        }
        edge = (edge * 3) / 4;
    }

    Err(format!(
        "Could not compress image under {max_kb} KB even after downscaling."
    ))
}
