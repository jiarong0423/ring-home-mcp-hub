# Face hint worker: OpenCV YuNet (find faces) + SFace (128-number feature per face), run locally on the Mac.
# One JSON request per line on stdin, one JSON answer per line on stdout. It never writes the image or the features anywhere;
# matching, consent, encryption and deletion live in src/face_hint.mjs. Run with python -I (see face_hint.mjs).
#   request : {"id": n, "image": "<base64 JPEG/PNG>"}
#   answer  : {"id": n, "faces": [{"score": 0.93, "box": [x, y, w, h], "feature": [128 floats]}]}  or  {"id": n, "error": "CODE"}
import base64
import binascii
import json
import sys

import cv2
import numpy as np

MAX_IMAGE_BYTES = 1_500_000
MAX_SIDE = 1280
MAX_FACES = 5
MAX_PIXELS = 4096 * 4096   # checked from the file header BEFORE decoding: a tiny file must not declare a huge canvas
MIN_SIDE = 64              # smaller images cannot hold a usable face; YuNet can report false faces on them


def declared_size(raw):
    """Width and height written in a PNG IHDR or a JPEG SOF header, or None when they cannot be read."""
    if raw[:8] == b'\x89PNG\r\n\x1a\n':
        if len(raw) < 24 or raw[12:16] != b'IHDR':
            return None
        return int.from_bytes(raw[16:20], 'big'), int.from_bytes(raw[20:24], 'big')
    i = 2
    while i + 9 < len(raw):
        if raw[i] != 0xFF:
            return None
        marker = raw[i + 1]
        if marker in (0xD8, 0x01) or 0xD0 <= marker <= 0xD7:
            i += 2
            continue
        length = int.from_bytes(raw[i + 2:i + 4], 'big')
        if 0xC0 <= marker <= 0xCF and marker not in (0xC4, 0xC8, 0xCC):
            return int.from_bytes(raw[i + 7:i + 9], 'big'), int.from_bytes(raw[i + 5:i + 7], 'big')
        if length < 2:
            return None
        i += 2 + length
    return None


def main(det_path, rec_path):
    detector = cv2.FaceDetectorYN.create(det_path, '', (320, 320), 0.8, 0.3, 5000)
    recognizer = cv2.FaceRecognizerSF.create(rec_path, '')
    sys.stdout.write(json.dumps({'ready': True, 'opencv': cv2.__version__}) + '\n')
    sys.stdout.flush()
    for line in sys.stdin:
        rid = None
        try:
            req = json.loads(line)
            rid = req.get('id')
            sys.stdout.write(json.dumps({'id': rid, **analyse(detector, recognizer, req.get('image'))}) + '\n')
        except Exception:  # never echo the input back; a fixed code is enough for the caller
            sys.stdout.write(json.dumps({'id': rid, 'error': 'FACE_WORKER_FAILED'}) + '\n')
        sys.stdout.flush()


def analyse(detector, recognizer, image_b64):
    if not isinstance(image_b64, str) or len(image_b64) > MAX_IMAGE_BYTES * 4 // 3 + 4:
        return {'error': 'IMAGE_INVALID'}
    try:
        raw = base64.b64decode(image_b64, validate=True)
    except (binascii.Error, ValueError):
        return {'error': 'IMAGE_INVALID'}
    if not raw or len(raw) > MAX_IMAGE_BYTES or not (raw[:3] == b'\xff\xd8\xff' or raw[:8] == b'\x89PNG\r\n\x1a\n'):
        return {'error': 'IMAGE_INVALID'}
    size = declared_size(raw)
    if size is None or min(size) < MIN_SIDE or size[0] * size[1] > MAX_PIXELS:
        return {'error': 'IMAGE_INVALID'}
    img = cv2.imdecode(np.frombuffer(raw, np.uint8), cv2.IMREAD_COLOR)
    if img is None or img.ndim != 3:
        return {'error': 'IMAGE_INVALID'}
    h, w = img.shape[:2]
    if max(h, w) > MAX_SIDE:
        scale = MAX_SIDE / max(h, w)
        img = cv2.resize(img, (max(1, int(w * scale)), max(1, int(h * scale))), interpolation=cv2.INTER_AREA)
        h, w = img.shape[:2]
    detector.setInputSize((w, h))
    _, found = detector.detect(img)
    faces = []
    if found is not None:
        for row in sorted(found, key=lambda r: -float(r[14]))[:MAX_FACES]:
            aligned = recognizer.alignCrop(img, row)
            feature = recognizer.feature(aligned).flatten()
            faces.append({'score': round(float(row[14]), 4), 'box': [int(v) for v in row[:4]],
                          'feature': [round(float(v), 6) for v in feature]})
    return {'faces': faces}


if __name__ == '__main__':
    if len(sys.argv) != 3:
        sys.stderr.write('usage: face_worker.py <yunet.onnx> <sface.onnx>\n')
        sys.exit(2)
    main(sys.argv[1], sys.argv[2])
