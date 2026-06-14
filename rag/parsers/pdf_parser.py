from typing import List
import os

import cv2
import numpy as np
import tqdm
from langchain_community.document_loaders.unstructured import UnstructuredFileLoader
from PIL import Image

from rag.parsers.ocr import get_ocr


class RapidOCRPDFLoader(UnstructuredFileLoader):
    def _get_elements(self) -> List:
        def rotate_img(img, angle):
            h, w = img.shape[:2]
            rotate_center = (w / 2, h / 2)

            M = cv2.getRotationMatrix2D(rotate_center, angle, 1.0)
            # Calculate new image boundaries
            new_w = int(h * np.abs(M[0, 1]) + w * np.abs(M[0, 0]))
            new_h = int(h * np.abs(M[0, 0]) + w * np.abs(M[0, 1]))
            # Adjust rotation matrix to account for translation
            M[0, 2] += (new_w - w) / 2
            M[1, 2] += (new_h - h) / 2

            rotated_img = cv2.warpAffine(img, M, (new_w, new_h))
            return rotated_img

        def pdf2text(filepath):
            import fitz  # fitz package from pyMuPDF
            import numpy as np

            ocr = get_ocr()
            doc = fitz.open(filepath)
            resp = ""

            b_unit = tqdm.tqdm(
                total=doc.page_count, desc="RapidOCRPDFLoader context page index: 0"
            )
            for i, page in enumerate(doc):
                b_unit.set_description(
                    "RapidOCRPDFLoader context page index: {}".format(i)
                )
                b_unit.refresh()
                text = page.get_text("")
                resp += text + "\n"

                # If OCR is available, try to extract text from images
                if ocr is not None:
                    img_list = page.get_image_info(xrefs=True)
                    for img in img_list:
                        try:
                            if xref := img.get("xref"):
                                bbox = img["bbox"]
                                # Only process images that are large enough
                                if (bbox[2] - bbox[0]) / (page.rect.width) < 0.6 or (bbox[3] - bbox[1]) / (
                                    page.rect.height
                                ) < 0.6:
                                    continue
                                
                                pix = fitz.Pixmap(doc, xref)
                                if int(page.rotation) != 0:
                                    img_array = np.frombuffer(
                                        pix.samples, dtype=np.uint8
                                    ).reshape(pix.height, pix.width, -1)
                                    tmp_img = Image.fromarray(img_array)
                                    ori_img = cv2.cvtColor(np.array(tmp_img), cv2.COLOR_RGB2BGR)
                                    rot_img = rotate_img(img=ori_img, angle=360 - page.rotation)
                                    img_array = cv2.cvtColor(rot_img, cv2.COLOR_RGB2BGR)
                                else:
                                    img_array = np.frombuffer(
                                        pix.samples, dtype=np.uint8
                                    ).reshape(pix.height, pix.width, -1)

                                result, _ = ocr(img_array)
                                if result:
                                    ocr_result = [line[1] for line in result]
                                    resp += "\n".join(ocr_result)
                        except Exception:
                            continue

                b_unit.update(1)
            return resp

        # Extract text locally from PDF
        text = pdf2text(self.file_path)
        
        # Disable Unstructured API calls
        os.environ['UNSTRUCTURED_API_KEY'] = ''
        
        from unstructured.partition.text import partition_text
        
        try:
            # Use 'fast' strategy to ensure local processing and avoid HTTP 403
            kwargs = self.unstructured_kwargs.copy()
            kwargs['strategy'] = 'fast'
            return partition_text(text=text, **kwargs)
        except Exception as e:
            # Fallback to a simple text element if sophisticated partitioning fails
            print(f"Warning: partition_text failed: {e}. Falling back to simple paragraph splitting.")
            from unstructured.documents.elements import Text
            paragraphs = [p.strip() for p in text.split('\n\n') if p.strip()]
            return [Text(text=para) for para in paragraphs]
