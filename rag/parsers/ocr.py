from typing import TYPE_CHECKING

if TYPE_CHECKING:
    try:
        from rapidocr_paddle import RapidOCR
    except ImportError:
        from rapidocr_onnxruntime import RapidOCR


def get_ocr(use_cuda: bool = True) -> "RapidOCR":
    try:
        from rapidocr_paddle import RapidOCR
        
        try:
            ocr = RapidOCR(
                det_use_cuda=use_cuda, cls_use_cuda=use_cuda, rec_use_cuda=use_cuda
            )
        except Exception as e:
            # If CUDA initialization fails or model download fails, fall back to CPU
            print(f"Warning: Failed to initialize RapidOCR with CUDA: {e}")
            print("Falling back to CPU mode...")
            ocr = RapidOCR(
                det_use_cuda=False, cls_use_cuda=False, rec_use_cuda=False
            )
    except ImportError:
        from rapidocr_onnxruntime import RapidOCR
        
        try:
            ocr = RapidOCR()
        except Exception as e:
            # If model download fails, print warning but continue
            print(f"Warning: Failed to initialize RapidOCR: {e}")
            print("OCR functionality may be limited.")
            ocr = None
    return ocr
