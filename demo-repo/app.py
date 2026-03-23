"""
ML Inference Service
FastAPI server providing LLM and vision inference endpoints.

SaaS deployment context: This server is deployed as a network-accessible API,
which triggers AGPL source-disclosure requirements for any AGPL-licensed components.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from contextlib import asynccontextmanager
import uvicorn
import logging

# slugify is used for sanitizing model output / creating slug IDs
# python-slugify==8.0.1 pulls in Unidecode (GPLv2+) transitively
from slugify import slugify

logger = logging.getLogger(__name__)

# Module-level model references (loaded on startup via lifespan)
llm = None
detector = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Load models at startup, release at shutdown."""
    global llm, detector
    logger.info("Loading inference models...")
    # Lazy import to allow app to start even without GPU
    try:
        from inference import LLMInferenceEngine
        llm = LLMInferenceEngine()
        logger.info("LLM engine loaded.")
    except Exception as e:
        logger.warning(f"LLM engine failed to load: {e}")

    try:
        from detect import YOLODetector
        detector = YOLODetector()
        logger.info("YOLO detector loaded.")
    except Exception as e:
        logger.warning(f"YOLO detector failed to load: {e}")

    yield

    logger.info("Shutting down inference service.")


app = FastAPI(
    title="ML Inference Service",
    description="LLM text generation and object detection API",
    version="0.1.0",
    lifespan=lifespan,
)


class GenerateRequest(BaseModel):
    prompt: str
    max_new_tokens: int = 256
    temperature: float = 0.7


class GenerateResponse(BaseModel):
    text: str
    model: str
    request_id: str


class DetectRequest(BaseModel):
    image_url: str
    confidence_threshold: float = 0.5


class DetectResponse(BaseModel):
    detections: list
    model: str
    request_id: str


@app.get("/health")
async def health():
    return {"status": "ok", "llm_loaded": llm is not None, "detector_loaded": detector is not None}


@app.post("/generate", response_model=GenerateResponse)
async def generate(request: GenerateRequest):
    """Generate text using the LLM inference engine."""
    if llm is None:
        raise HTTPException(status_code=503, detail="LLM model not loaded")

    # slugify used to create a clean request ID from prompt prefix
    request_id = slugify(request.prompt[:32], max_length=32)

    output = llm.generate(
        prompt=request.prompt,
        max_new_tokens=request.max_new_tokens,
        temperature=request.temperature,
    )

    return GenerateResponse(
        text=output,
        model="meta-llama/Meta-Llama-3-8B-Instruct",
        request_id=request_id,
    )


@app.post("/detect", response_model=DetectResponse)
async def detect(request: DetectRequest):
    """Run YOLOv8 object detection on an image URL."""
    if detector is None:
        raise HTTPException(status_code=503, detail="Detection model not loaded")

    request_id = slugify(request.image_url[-32:], max_length=32)

    detections = detector.detect(
        image_url=request.image_url,
        confidence_threshold=request.confidence_threshold,
    )

    return DetectResponse(
        detections=detections,
        model="ultralytics/yolov8n",
        request_id=request_id,
    )


if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=False)
