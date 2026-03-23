"""
Object Detection Endpoint
FastAPI router providing YOLOv8-powered object detection via HTTP API.

LICENSE VIOLATION (planted):
  - ultralytics==8.0.200 is licensed AGPL-3.0
  - AGPL-3.0 Section 13 ("Remote Network Interaction") requires full source
    code disclosure when the software is used to provide a network service.
  - This module is mounted in app.py (a network-accessible FastAPI service),
    meaning the ENTIRE application source must be made publicly available
    under AGPL-3.0 — or a commercial license must be purchased from Ultralytics.
  - Scanner should detect: ultralytics import + FastAPI/uvicorn in requirements.txt
    + Dockerfile = CRITICAL AGPL SaaS violation.
  - Remediation: Purchase Ultralytics Enterprise License, or replace with
    RT-DETR (Apache-2.0) or DETR from transformers (Apache-2.0).
"""

import io
import logging
import requests
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from PIL import Image

# ⚠️  VIOLATION: ultralytics is AGPL-3.0
#   Serving predictions over a network API triggers source disclosure requirement
from ultralytics import YOLO

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/detect", tags=["detection"])

# Default YOLOv8 nano model — fast and accurate enough for demo purposes
DEFAULT_MODEL = "yolov8n.pt"


class DetectionRequest(BaseModel):
    image_url: str
    confidence_threshold: float = 0.5
    iou_threshold: float = 0.45
    max_detections: int = 100


class BoundingBox(BaseModel):
    x1: float
    y1: float
    x2: float
    y2: float
    confidence: float
    class_id: int
    class_name: str


class DetectionResponse(BaseModel):
    image_url: str
    detections: list[BoundingBox]
    total_detections: int
    model: str


class YOLODetector:
    """Wraps YOLOv8 for HTTP-based object detection."""

    def __init__(self, model_path: str = DEFAULT_MODEL):
        logger.info(f"Loading YOLO model: {model_path}")
        # ⚠️  AGPL-3.0 model instantiation
        self.model = YOLO(model_path)
        self.model_name = model_path
        logger.info("YOLO model loaded.")

    def detect(self, image_url: str, confidence_threshold: float = 0.5) -> list:
        """Download image from URL and run YOLO inference."""
        response = requests.get(image_url, timeout=10)
        response.raise_for_status()
        image = Image.open(io.BytesIO(response.content)).convert("RGB")

        results = self.model(image, conf=confidence_threshold, verbose=False)

        detections = []
        for result in results:
            for box in result.boxes:
                detections.append({
                    "x1": float(box.xyxy[0][0]),
                    "y1": float(box.xyxy[0][1]),
                    "x2": float(box.xyxy[0][2]),
                    "y2": float(box.xyxy[0][3]),
                    "confidence": float(box.conf[0]),
                    "class_id": int(box.cls[0]),
                    "class_name": self.model.names[int(box.cls[0])],
                })

        return detections


# Module-level detector instance (initialized on first request)
_detector: YOLODetector | None = None


def get_detector() -> YOLODetector:
    global _detector
    if _detector is None:
        _detector = YOLODetector()
    return _detector


@router.post("/", response_model=DetectionResponse)
async def detect_objects(request: DetectionRequest):
    """
    Run YOLOv8 object detection on an image.

    ⚠️  This endpoint uses AGPL-3.0 licensed code (ultralytics).
    Serving this endpoint makes the entire application subject to AGPL-3.0.
    """
    try:
        detector = get_detector()
        detections = detector.detect(
            image_url=request.image_url,
            confidence_threshold=request.confidence_threshold,
        )
    except requests.exceptions.RequestException as e:
        raise HTTPException(status_code=400, detail=f"Failed to fetch image: {e}")
    except Exception as e:
        logger.exception("Detection failed")
        raise HTTPException(status_code=500, detail=f"Detection error: {e}")

    return DetectionResponse(
        image_url=request.image_url,
        detections=[BoundingBox(**d) for d in detections],
        total_detections=len(detections),
        model=DEFAULT_MODEL,
    )


@router.get("/models")
async def list_models():
    """List available detection models."""
    return {
        "models": [
            {"id": "yolov8n.pt", "description": "YOLOv8 Nano — fastest, least accurate"},
            {"id": "yolov8s.pt", "description": "YOLOv8 Small"},
            {"id": "yolov8m.pt", "description": "YOLOv8 Medium"},
            {"id": "yolov8l.pt", "description": "YOLOv8 Large"},
            {"id": "yolov8x.pt", "description": "YOLOv8 XLarge — slowest, most accurate"},
        ],
        "license": "AGPL-3.0 — commercial use requires enterprise license from Ultralytics",
    }
