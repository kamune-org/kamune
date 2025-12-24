# Kamune Application Icons

This directory should contain the application icons in various formats for different platforms.

## Required Icons

| Filename | Size | Platform |
|----------|------|----------|
| `32x32.png` | 32x32 px | All |
| `128x128.png` | 128x128 px | All |
| `128x128@2x.png` | 256x256 px | macOS Retina |
| `icon.icns` | Multi-size | macOS |
| `icon.ico` | Multi-size | Windows |

## Generating Icons

### Using Tauri CLI

The easiest way to generate all required icons is to use the Tauri icon command with a source PNG (1024x1024 recommended):

```bash
cargo tauri icon path/to/source-icon.png
```

This will generate all required formats automatically.

### Manual Generation

#### macOS (.icns)

```bash
# Create iconset directory
mkdir icon.iconset
sips -z 16 16     icon-1024.png --out icon.iconset/icon_16x16.png
sips -z 32 32     icon-1024.png --out icon.iconset/icon_16x16@2x.png
sips -z 32 32     icon-1024.png --out icon.iconset/icon_32x32.png
sips -z 64 64     icon-1024.png --out icon.iconset/icon_32x32@2x.png
sips -z 128 128   icon-1024.png --out icon.iconset/icon_128x128.png
sips -z 256 256   icon-1024.png --out icon.iconset/icon_128x128@2x.png
sips -z 256 256   icon-1024.png --out icon.iconset/icon_256x256.png
sips -z 512 512   icon-1024.png --out icon.iconset/icon_256x256@2x.png
sips -z 512 512   icon-1024.png --out icon.iconset/icon_512x512.png
sips -z 1024 1024 icon-1024.png --out icon.iconset/icon_512x512@2x.png
iconutil -c icns icon.iconset
```

#### Windows (.ico)

Use ImageMagick:

```bash
convert icon-1024.png -resize 256x256 \
    -define icon:auto-resize=256,128,64,48,32,16 \
    icon.ico
```

#### Linux PNGs

```bash
convert icon-1024.png -resize 32x32 32x32.png
convert icon-1024.png -resize 128x128 128x128.png
convert icon-1024.png -resize 256x256 128x128@2x.png
```

## Placeholder

Until proper icons are created, the application will use default Tauri icons. For production, replace these with branded Kamune icons.