#!/usr/bin/env python3
"""
Render film.html frame by frame (Playwright) and encode with ffmpeg.

  python render.py probe 1 5 10 15 22 28   -> out/probe/sheet.png (stills to check)
  python render.py cues                    -> out/cues.json (sound cues for audio.py)
  python render.py full [fps] [subframes]  -> out/video.mp4 (default 30 fps, 4 subframes)
  python render.py mux                     -> out/loanwatch_film.mp4 (video + out/audio.wav)
  python render.py contact                 -> out/contact.png (2 fps contact sheet of the final)

Every frame is a pure function of time (window.seek(t)), so renders are repeatable.
"""
import functools
import http.server
import json
import os
import subprocess
import sys
import threading

import imageio_ffmpeg
import numpy as np
from PIL import Image
from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
W, H, DURATION = 1080, 1350, 35.0
SHUTTER = 0.5          # 180-degree shutter: subframes spread over half a frame
FFMPEG = imageio_ffmpeg.get_ffmpeg_exe()
CHROMIUM = os.environ.get("CHROMIUM", "/opt/pw-browsers/chromium")


def serve():
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=HERE)
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, f"http://127.0.0.1:{srv.server_address[1]}/film.html"


class Film:
    def __enter__(self):
        self.srv, url = serve()
        self.pw = sync_playwright().start()
        kw = {"executable_path": CHROMIUM} if os.path.exists(CHROMIUM) else {}
        self.browser = self.pw.chromium.launch(args=[
            "--font-render-hinting=none", "--force-color-profile=srgb",
            "--disable-threaded-animation", "--run-all-compositor-stages-before-draw"], **kw)
        self.page = self.browser.new_page(viewport={"width": W, "height": H}, device_scale_factor=1)
        self.page.goto(url)
        self.page.wait_for_function("window.ready === true", timeout=30000)
        self.page.evaluate("document.fonts.ready")
        return self

    def frame(self, t):
        self.page.evaluate("t => window.seek(t)", t)
        # two animation frames so layout and paint settle before capture
        self.page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")
        png = self.page.screenshot(type="png")
        from io import BytesIO
        return np.asarray(Image.open(BytesIO(png)).convert("RGB"))

    def __exit__(self, *a):
        self.browser.close()
        self.pw.stop()
        self.srv.shutdown()


def probe(times):
    os.makedirs(os.path.join(OUT, "probe"), exist_ok=True)
    tiles = []
    with Film() as f:
        for t in times:
            img = Image.fromarray(f.frame(float(t)))
            img.save(os.path.join(OUT, "probe", f"t{float(t):05.2f}.png"))
            tiles.append(img.resize((W // 3, H // 3)))
    cols = min(4, len(tiles))
    rows = (len(tiles) + cols - 1) // cols
    sheet = Image.new("RGB", (cols * W // 3, rows * H // 3), "black")
    for i, im in enumerate(tiles):
        sheet.paste(im, ((i % cols) * W // 3, (i // cols) * H // 3))
    sheet.save(os.path.join(OUT, "probe", "sheet.png"))
    print("wrote out/probe/sheet.png")


def cues():
    os.makedirs(OUT, exist_ok=True)
    with Film() as f:
        data = f.page.evaluate("window.CUES")
    with open(os.path.join(OUT, "cues.json"), "w") as fh:
        json.dump(data, fh, indent=1)
    print(f"wrote out/cues.json ({len(data)} cues)")


def full(fps=30, subframes=4):
    os.makedirs(OUT, exist_ok=True)
    n = int(round(DURATION * fps))
    path = os.path.join(OUT, "video.mp4")
    enc = subprocess.Popen([
        FFMPEG, "-y", "-loglevel", "error", "-f", "rawvideo", "-pix_fmt", "rgb24", "-s", f"{W}x{H}",
        "-r", str(fps), "-i", "-",
        "-vf", "scale=in_range=pc:out_range=tv:out_color_matrix=bt709,format=yuv420p",
        "-c:v", "libx264", "-preset", "slow", "-crf", "16",
        "-color_range", "tv", "-colorspace", "bt709", "-color_primaries", "bt709", "-color_trc", "bt709",
        "-movflags", "+faststart", path], stdin=subprocess.PIPE)
    with Film() as f:
        for i in range(n):
            t = i / fps
            if subframes > 1:
                acc = np.zeros((H, W, 3), np.float32)
                for s in range(subframes):
                    acc += f.frame(min(DURATION, t + (s / subframes) * SHUTTER / fps))
                img = (acc / subframes + .5).astype(np.uint8)
            else:
                img = f.frame(t)
            enc.stdin.write(img.tobytes())
            if i % fps == 0:
                print(f"  {i / fps:4.0f}s / {DURATION:.0f}s", flush=True)
    enc.stdin.close()
    enc.wait()
    print(f"wrote {path}")


def mux():
    v, a = os.path.join(OUT, "video.mp4"), os.path.join(OUT, "audio.wav")
    dst = os.path.join(OUT, "loanwatch_film.mp4")
    subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-i", v, "-i", a, "-map", "0:v", "-map", "1:a",
                    "-c:v", "copy", "-c:a", "aac", "-b:a", "256k", "-movflags", "+faststart", dst], check=True)
    print(f"wrote {dst}")


def contact():
    src = os.path.join(OUT, "loanwatch_film.mp4")
    if not os.path.exists(src):
        src = os.path.join(OUT, "video.mp4")
    subprocess.run([FFMPEG, "-y", "-loglevel", "error", "-i", src, "-vf",
                    "fps=2,scale=216:-1,tile=10x6", "-frames:v", "1", os.path.join(OUT, "contact.png")], check=True)
    print("wrote out/contact.png")


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "probe"
    if cmd == "probe":
        probe(sys.argv[2:] or [1.5, 5.5, 10.8, 17, 23.5, 29])
    elif cmd == "cues":
        cues()
    elif cmd == "full":
        full(int(sys.argv[2]) if len(sys.argv) > 2 else 30, int(sys.argv[3]) if len(sys.argv) > 3 else 4)
    elif cmd == "mux":
        mux()
    elif cmd == "contact":
        contact()
    else:
        sys.exit(__doc__)
