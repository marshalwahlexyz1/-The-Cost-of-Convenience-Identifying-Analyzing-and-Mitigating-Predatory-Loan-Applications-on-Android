#!/usr/bin/env python3
"""
Synthesize the film's sound from out/cues.json (written by `render.py cues`).
Every sound is generated in code (no samples, no licences) and placed on the
exact time its visual event happens, then loudness-normalised to -14 LUFS.

  python audio.py   -> out/audio.wav
"""
import json
import os
import subprocess
import wave

import imageio_ffmpeg
import numpy as np

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "out")
SR = 48000
DURATION = 35.0
rng = np.random.default_rng(7)          # seeded: identical output every run


def env(n, attack=0.004, decay=0.15):
    t = np.arange(n) / SR
    a = np.clip(t / attack, 0, 1)
    return a * np.exp(-t / decay)


def tone(f0, f1, dur, decay, gain=1.0, shape="sine"):
    n = int(dur * SR)
    f = np.geomspace(f0, f1, n)
    ph = 2 * np.pi * np.cumsum(f) / SR
    w = np.sin(ph) if shape == "sine" else np.sign(np.sin(ph)) * .3 + np.sin(ph) * .7
    return w * env(n, .003, decay) * gain


def noise(dur, lo, hi, attack, decay, gain=1.0, sweep=None):
    n = int(dur * SR)
    x = rng.standard_normal(n)
    spec = np.fft.rfft(x)
    freqs = np.fft.rfftfreq(n, 1 / SR)
    band = ((freqs > lo) & (freqs < hi)).astype(float)
    y = np.fft.irfft(spec * band, n)
    y /= np.max(np.abs(y)) + 1e-9
    if sweep:                                   # amplitude swell for whooshes
        t = np.linspace(0, 1, n)
        y *= np.sin(np.pi * t) ** sweep
    return y * env(n, attack, decay) * gain


def mixdown(*parts):
    """Sum sounds of different lengths (shorter ones are zero-padded)."""
    n = max(len(p) for p in parts)
    out = np.zeros(n)
    for p in parts:
        out[:len(p)] += p
    return out


SOUNDS = {
    "whoosh":  lambda: noise(.35, 500, 6000, .08, .25, .5, sweep=1.5),
    "swoosh":  lambda: noise(.45, 300, 5000, .12, .3, .6, sweep=2),
    "sweep":   lambda: noise(.8, 1500, 9000, .3, .6, .25, sweep=1.2),
    "flip":    lambda: mixdown(noise(.12, 1500, 7000, .002, .04, .6), tone(900, 700, .1, .03, .2)),
    "click":   lambda: mixdown(tone(2200, 1800, .05, .012, .7), noise(.04, 3000, 9000, .001, .01, .3)),
    "pop":     lambda: tone(520, 980, .12, .05, .7),
    "tick":    lambda: tone(1400, 1300, .05, .015, .5),
    "alert":   lambda: np.concatenate([tone(880, 880, .09, .05, .5), tone(660, 660, .16, .08, .5)]),
    "thump":   lambda: mixdown(tone(140, 48, .45, .16, 1.0), noise(.05, 800, 4000, .001, .01, .15)),
    "impact":  lambda: mixdown(tone(110, 38, 1.2, .45, 1.0), noise(.6, 200, 3000, .002, .18, .25)),
    "sparkle": lambda: mixdown(*(tone(f, f * 1.01, .6, .25, .12) for f in (1568, 2093, 2637, 3136))),
    "pulse":   lambda: tone(70, 45, .35, .12, .5),
}


def place(track, x, t, gain):
    i = int(round(t * SR))
    peak = int(np.argmax(np.abs(x)))          # align the sound's peak with the cue
    i = max(0, i - peak)
    j = min(len(track), i + len(x))
    track[i:j] += x[: j - i] * gain


def main():
    with open(os.path.join(OUT, "cues.json")) as f:
        cues = json.load(f)
    track = np.zeros(int(DURATION * SR))
    for c in cues:
        place(track, SOUNDS[c["kind"]](), c["t"], c["gain"])
    # a quiet low pad under the scan for tension, faded in and out
    t = np.arange(len(track)) / SR
    pad = (np.sin(2 * np.pi * 55 * t) + .5 * np.sin(2 * np.pi * 82.4 * t)) * .05
    pad *= np.clip((t - 13.5) / 1.0, 0, 1) * np.clip((20.0 - t) / 1.0, 0, 1)
    track += pad
    # fade the tail
    tail = int(1.2 * SR)
    track[-tail:] *= np.linspace(1, 0, tail)
    track /= np.max(np.abs(track)) + 1e-9
    stereo = np.stack([track, track], axis=1) * .9
    raw = os.path.join(OUT, "audio_raw.wav")
    with wave.open(raw, "wb") as w:
        w.setnchannels(2); w.setsampwidth(2); w.setframerate(SR)
        w.writeframes((stereo * 32767).astype("<i2").tobytes())
    # two-pass loudness normalisation to -14 LUFS, true peak -1.5 dB
    ff = imageio_ffmpeg.get_ffmpeg_exe()
    first = subprocess.run([ff, "-i", raw, "-af", "loudnorm=I=-14:TP=-1.5:LRA=11:print_format=json",
                            "-f", "null", "-"], capture_output=True, text=True).stderr
    m = json.loads(first[first.rindex("{"):first.rindex("}") + 1])
    af = ("loudnorm=I=-14:TP=-1.5:LRA=11:measured_I={input_i}:measured_TP={input_tp}:"
          "measured_LRA={input_lra}:measured_thresh={input_thresh}:offset={target_offset}:linear=true").format(**m)
    subprocess.run([ff, "-y", "-loglevel", "error", "-i", raw, "-af", af, "-ar", str(SR),
                    os.path.join(OUT, "audio.wav")], check=True)
    os.remove(raw)
    print(f"wrote out/audio.wav ({len(cues)} cues, measured {m['input_i']} LUFS before normalising)")


if __name__ == "__main__":
    main()
