#!/usr/bin/env python3
"""Deterministic OpenCV template matching for CI screenshot assertions."""
import json
import sys

try:
    import cv2
except Exception as exc:  # pragma: no cover - environment dependent
    print(json.dumps({"available": False, "error": f"cv2 import failed: {exc}"}))
    sys.exit(2)

if len(sys.argv) != 3:
    print("Usage: opencv-match.py IMAGE TEMPLATE", file=sys.stderr)
    sys.exit(2)

image_path, template_path = sys.argv[1], sys.argv[2]
image = cv2.imread(image_path, cv2.IMREAD_GRAYSCALE)
template = cv2.imread(template_path, cv2.IMREAD_GRAYSCALE)
if image is None:
    print(f"Could not read image: {image_path}", file=sys.stderr)
    sys.exit(1)
if template is None:
    print(f"Could not read template: {template_path}", file=sys.stderr)
    sys.exit(1)
if template.shape[0] > image.shape[0] or template.shape[1] > image.shape[1]:
    print(json.dumps({
        "available": True,
        "method": "TM_CCOEFF_NORMED",
        "score": -1,
        "location": None,
        "image": {"width": int(image.shape[1]), "height": int(image.shape[0])},
        "template": {"width": int(template.shape[1]), "height": int(template.shape[0])},
        "error": "template larger than image"
    }))
    sys.exit(0)

result = cv2.matchTemplate(image, template, cv2.TM_CCOEFF_NORMED)
_min_val, max_val, _min_loc, max_loc = cv2.minMaxLoc(result)
print(json.dumps({
    "available": True,
    "method": "TM_CCOEFF_NORMED",
    "score": float(max_val),
    "location": {"x": int(max_loc[0]), "y": int(max_loc[1])},
    "image": {"width": int(image.shape[1]), "height": int(image.shape[0])},
    "template": {"width": int(template.shape[1]), "height": int(template.shape[0])}
}))
