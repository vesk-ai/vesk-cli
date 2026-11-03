# Image prompts

The site ships with **no real images**. The hero and modules banner are **optional slots**: the page already has built-in animated SVG artwork (hero orbit, one illustration per module), so nothing looks broken without them. When you add a file with the exact name below, it appears automatically (the hero image replaces the orbit artwork; the banner shows under the modules).
To use an image: save it in `site/img/` with the **exact file name** below. No code change needed. Nothing new is required for this design pass; sizes are updated to match the new slots.

Style guide for all images (keeps them consistent with the site): dark navy background (#0b1020), teal (#5eead4) and violet (#a78bfa) accents, clean geometric/technical look, no text, no logos, no people's faces, no real brand names. Export as WebP, under about 200 KB.

| File | Size (px) / aspect | Used in |
|---|---|---|
| `hero-visual.webp` | 1600×1200 (4:3), display ~800×600 | Hero, right of the headline (fills a square area, cropped to fit; keep the subject centred) |
| `modules-banner.webp` | 2520×1080 (21:9), display ~1120 wide | Under the four module showcases |

## hero-visual.webp
**Prompt:** Abstract isometric illustration of a glowing neural-network core floating above a dark navy grid, surrounded by four translucent verification rings and a thin trail of light that loops back into itself like an audit trail. Deep navy background (#0b1020), teal (#5eead4) and violet (#a78bfa) accent lights, soft depth of field, minimal, precise, high-end technology look. No text, no letters, no logos, no people. 4:3 aspect ratio.

## modules-banner.webp
**Prompt:** Wide panoramic minimalist illustration of four connected stages in a horizontal loop: a checklist shield, a magnifying lens over a flow of data, a lock gate on a data stream, and a ledger of stacked records. Linked by glowing teal lines on a dark navy background (#0b1020) with violet accents. Flat-geometric style with subtle gradients, lots of empty space. No text, no letters, no logos. 21:9 aspect ratio.

## Optional later: social preview (not wired up)
`og-image.png`, 1200×630 (1.91:1). **Prompt:** Dark navy background (#0b1020) with an abstract teal and violet glowing loop symbol at centre-left and empty space on the right for a title to be added later. No text. If you add it, also add `<meta property="og:image" content="https://vesktechnologies.com/og-image.png">` to `site/index.html`.
