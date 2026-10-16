#!/usr/bin/env bash
# Encode the raw Playwright recording into the files shipped with the docs.
#   input : demo/out/raw/*/video.webm  (+ demo/out/suspicious-demo.{vtt,srt})
#   output: ../docs/assets/demo/
set -euo pipefail

cd "$(dirname "$0")/.."
RAW=$(ls -t demo/out/raw/*/video.webm | head -n1)
DEST=../docs/assets/demo
mkdir -p "$DEST"

# Full video: H.264 + faststart so it streams from GitHub Pages. UI footage is
# mostly static, so a high CRF keeps it small without visible artefacts.
ffmpeg -v error -y -i "$RAW" \
  -c:v libx264 -preset slow -crf 27 -pix_fmt yuv420p -r 25 \
  -movflags +faststart -an "$DEST/suspicious-demo.mp4"

# Poster frame for <video poster=...>: the script marks a caption-free moment.
POSTER_AT=$(python3 -c "import json; print(json.load(open('demo/out/suspicious-demo.marks.json')).get('poster', 36))")
ffmpeg -v error -y -ss "$POSTER_AT" -i "$DEST/suspicious-demo.mp4" -frames:v 1 \
  -vf "scale=1280:-1" -q:v 3 "$DEST/suspicious-demo-poster.jpg"

# README teaser: a short, sped-up GIF (GitHub cannot inline a repo-hosted video).
# Captions would be unreadable at this speed; the GIF links to the full video.
ffmpeg -v error -y -i "$DEST/suspicious-demo.mp4" \
  -vf "setpts=PTS/4,fps=8,scale=720:-1:flags=lanczos,split[a][b];[a]palettegen=max_colors=96:stats_mode=diff[p];[b][p]paletteuse=dither=bayer:bayer_scale=4" \
  -loop 0 "$DEST/suspicious-demo-teaser.gif"

cp demo/out/suspicious-demo.vtt demo/out/suspicious-demo.srt "$DEST/"
ls -lh "$DEST"
