from __future__ import annotations

import copy
from typing import Any

GRADING_MAPPING_VERSION = 1
UNMAPPED_REVIEW_LEVEL = "unmapped"
REVIEW_LEVEL_RANK = {
    "error": 4,
    "warning": 3,
    "style": 2,
    "information": 1,
    UNMAPPED_REVIEW_LEVEL: 0,
}


_REFERENCE: dict[str, Any] = {
    "id": "nxp-imxrt700-ava-tp-v1.1-code-analysis",
    "mapping_version": GRADING_MAPPING_VERSION,
    "document": {
        "file_name": "NXP_iMXRT700-AVA_TP_v1.1 (1).pdf",
        "title": "NXP i.MX RT700 SESIP Level 3 - AVA Test Plan",
        "author": "DEKRA Testing and Certification S.A.U.",
        "version": "1.1",
        "date": "2026-07-07",
        "sha256": "54c9cff44e72b489ab95f5f309ee9043508cc7657fb662092c6fc57b19540f35",
    },
    "section": {
        "number": "7",
        "title": "Code analysis",
        "grading_subsections": [
            {"number": "7.4.1", "title": "Security Levels", "pdf_pages": "26-27"},
            {"number": "7.4.2", "title": "Issue Categorization", "pdf_pages": "27-29"},
        ],
    },
    "levels": [
        {
            "id": "error",
            "label": "Error",
            "rank": REVIEW_LEVEL_RANK["error"],
            "description": "Requires immediate review because the issue may cause serious runtime failures; missing build context can still make individual cases false positives.",
        },
        {
            "id": "warning",
            "label": "Warning",
            "rank": REVIEW_LEVEL_RANK["warning"],
            "description": "Potentially compromises code during execution and should be reviewed with attention to its actual use.",
        },
        {
            "id": "style",
            "label": "Style",
            "rank": REVIEW_LEVEL_RANK["style"],
            "description": "Coding-practice or optimization concern without a direct security impact, but capable of contributing to unwanted behavior.",
        },
        {
            "id": "information",
            "label": "Information",
            "rank": REVIEW_LEVEL_RANK["information"],
            "description": "Often caused by incomplete external dependencies or analysis context; it still requires verification before being dismissed.",
        },
    ],
    "application": {
        "method": "exact-native-level",
        "mapped_native_levels": ["information", "style", "warning", "error"],
        "unmapped_label": "Unmapped",
        "manual_verification_required": True,
        "note": "Only an exact native level named by the reference is mapped. Numeric or tool-specific scales remain unmapped and retain their native and normalized severity fields.",
    },
}


def grading_reference() -> dict[str, Any]:
    return copy.deepcopy(_REFERENCE)


def reference_review_level(native_severity: Any) -> str:
    raw = str(native_severity or "").strip().lower()
    return raw if raw in {"information", "style", "warning", "error"} else UNMAPPED_REVIEW_LEVEL
