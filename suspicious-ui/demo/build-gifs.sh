#!/usr/bin/env bash
# Encode demo/out/gifs/<name>.webm (from pages.demo.ts) into optimised GIFs.
#   output: ../docs/assets/gifs/<name>.gif
# Each clip is trimmed with the start/end marks the script wrote next to it.
set -euo pipefail

cd "$(dirname "$0")/.."
SRC=demo/out/gifs
DEST=../docs/assets/gifs
FPS=${GIF_FPS:-10}
WIDTH=${GIF_WIDTH:-720}
COLORS=${GIF_COLORS:-96}
mkdir -p "$DEST"

for webm in "$SRC"/*.webm; do
  name=$(basename "$webm" .webm)
  read -r start end < <(python3 -c "import json,sys; m=json.load(open(sys.argv[1])); print(m.get('start',0), m['end'])" "$SRC/$name.json")
  # Palette from changed regions only (diff stats) keeps the mostly-static UI small.
  ffmpeg -v error -y -ss "$start" -to "$end" -i "$webm" \
    -vf "fps=$FPS,scale=$WIDTH:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=$COLORS:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4:diff_mode=rectangle" \
    -loop 0 "$DEST/$name.gif"
done
ls -lh "$DEST"
du -sh "$DEST"
