import streamlit as st
import hashlib
import platform
import sqlite3
import io
import csv
import re
import json
import ipaddress
from datetime import datetime
from pathlib import Path

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
except ImportError:
    Image = None
    TAGS = {}


# ============================================================
# 1. PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="DFIR Explorer",
    page_icon="🔎",
    layout="wide",
    initial_sidebar_state="expanded"
)

DB_PATH = Path(__file__).resolve().parent / "dfir_evidence.db"


# ============================================================
# 2. DATABASE
# ============================================================

def init_db():
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS evidence_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                category TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                details TEXT DEFAULT '',
                UNIQUE(sha256, category)
            )
        """)


def calculate_hash(file_bytes):
    return hashlib.sha256(file_bytes).hexdigest()


def save_record(filename, file_bytes, category, details=""):
    file_hash = calculate_hash(file_bytes)
    created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    try:
        with sqlite3.connect(DB_PATH) as connection:
            connection.execute("""
                INSERT INTO evidence_records
                (filename, category, sha256, size_bytes, created_at, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                filename,
                category,
                file_hash,
                len(file_bytes),
                created_at,
                details
            ))

        return True

    except sqlite3.IntegrityError:
        return False


def get_records():
    with sqlite3.connect(DB_PATH) as connection:
        connection.row_factory = sqlite3.Row

        rows = connection.execute("""
            SELECT filename, category, sha256, size_bytes, created_at, details
            FROM evidence_records
            ORDER BY id DESC
        """).fetchall()

    return [
        {
            "Filename": row["filename"],
            "Category": row["category"],
            "SHA-256": row["sha256"],
            "Size (bytes)": row["size_bytes"],
            "Date and Time": row["created_at"],
            "Details": row["details"]
        }
        for row in rows
    ]


def clear_records():
    with sqlite3.connect(DB_PATH) as connection:
        connection.execute("DELETE FROM evidence_records")


init_db()


# ============================================================
# 3. FILE SIGNATURE DATABASE
# ============================================================

SIGNATURES = [
    {
        "name": "PNG Image",
        "description": "Portable Network Graphics image",
        "extensions": {"png"},
        "signature": b"\x89PNG\r\n\x1a\n"
    },
    {
        "name": "JPEG Image",
        "description": "JPEG image",
        "extensions": {"jpg", "jpeg", "jpe"},
        "signature": b"\xff\xd8\xff"
    },
    {
        "name": "GIF Image",
        "description": "Graphics Interchange Format image",
        "extensions": {"gif"},
        "signature": (b"GIF87a", b"GIF89a")
    },
    {
        "name": "BMP Image",
        "description": "Bitmap image",
        "extensions": {"bmp", "dib"},
        "signature": b"BM"
    },
    {
        "name": "PDF Document",
        "description": "Portable Document Format",
        "extensions": {"pdf"},
        "signature": b"%PDF-"
    },
    {
        "name": "ZIP Archive",
        "description": "ZIP archive or ZIP-based file",
        "extensions": {
            "zip", "docx", "xlsx", "pptx", "apk",
            "jar", "epub", "odt", "ods"
        },
        "signature": (
            b"PK\x03\x04",
            b"PK\x05\x06",
            b"PK\x07\x08"
        )
    },
    {
        "name": "RAR Archive",
        "description": "RAR compressed archive",
        "extensions": {"rar"},
        "signature": (
            b"Rar!\x1a\x07\x00",
            b"Rar!\x1a\x07\x01\x00"
        )
    },
    {
        "name": "7-Zip Archive",
        "description": "7-Zip compressed archive",
        "extensions": {"7z"},
        "signature": b"7z\xbc\xaf\x27\x1c"
    },
    {
        "name": "GZIP Archive",
        "description": "GZIP compressed data",
        "extensions": {"gz", "gzip"},
        "signature": b"\x1f\x8b"
    },
    {
        "name": "Linux ELF File",
        "description": "Executable and Linkable Format",
        "extensions": {"elf", "so", "o", "bin"},
        "signature": b"\x7fELF"
    },
    {
        "name": "Windows Executable Family",
        "description": "Windows executable-family file",
        "extensions": {"exe", "dll", "sys", "scr", "com", "ocx"},
        "signature": b"MZ"
    },
    {
        "name": "SQLite Database",
        "description": "SQLite database file",
        "extensions": {"db", "sqlite", "sqlite3"},
        "signature": b"SQLite format 3\x00"
    },
    {
        "name": "WAV Audio",
        "description": "WAV audio file",
        "extensions": {"wav"},
        "signature": b"RIFF"
    },
    {
        "name": "MP3 Audio",
        "description": "MP3 audio file",
        "extensions": {"mp3"},
        "signature": (
            b"ID3",
            b"\xff\xfb",
            b"\xff\xf3",
            b"\xff\xf2"
        )
    },
    {
        "name": "MP4/QuickTime Media",
        "description": "ISO Base Media or QuickTime container",
        "extensions": {"mp4", "m4v", "mov", "m4a", "3gp"},
        "signature": b"ftyp",
        "offset": 4
    },
    {
        "name": "Microsoft Compound File",
        "description": "Older Microsoft Office document container",
        "extensions": {"doc", "xls", "ppt", "msg", "ole"},
        "signature": b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    }
]


def signature_matches(file_bytes, signature):
    if isinstance(signature, tuple):
        return any(file_bytes.startswith(item) for item in signature)

    return file_bytes.startswith(signature)


def identify_file_signature(file_bytes, filename):
    extension = Path(filename).suffix.lower().lstrip(".")

    for item in SIGNATURES:
        signature = item["signature"]
        offset = item.get("offset", 0)

        if offset:
            if len(file_bytes) >= offset + len(signature):
                if file_bytes[offset:offset + len(signature)] == signature:
                    matched = extension in item["extensions"]

                    return {
                        "Detected Type": item["name"],
                        "Description": item["description"],
                        "Extension": extension or "No extension",
                        "Result": (
                            "MATCH" if matched
                            else "POSSIBLE MISMATCH"
                        )
                    }

        elif signature_matches(file_bytes, signature):
            matched = extension in item["extensions"]

            return {
                "Detected Type": item["name"],
                "Description": item["description"],
                "Extension": extension or "No extension",
                "Result": (
                    "MATCH" if matched
                    else "POSSIBLE MISMATCH"
                )
            }

    if b"\x00" not in file_bytes[:4096]:
        try:
            file_bytes[:4096].decode("utf-8")

            return {
                "Detected Type": "Text-like content",
                "Description": "Opening bytes appear to contain UTF-8 text.",
                "Extension": extension or "No extension",
                "Result": "TEXT-LIKE CONTENT"
            }

        except UnicodeDecodeError:
            pass

    return {
        "Detected Type": "Unknown",
        "Description": "No supported signature was detected.",
        "Extension": extension or "No extension",
        "Result": "NOT IDENTIFIED"
    }


# ============================================================
# 4. FORENSIC ARTEFACT EXTRACTION
# ============================================================

def extract_image_metadata(file_bytes):
    results = {
        "Analysis Status": "Not available",
        "Image Format": None,
        "Width": None,
        "Height": None,
        "Color Mode": None,
        "EXIF Metadata": {}
    }

    if Image is None:
        results["Analysis Status"] = "Pillow is not installed"
        return results

    try:
        with Image.open(io.BytesIO(file_bytes)) as image:
            results["Analysis Status"] = "Successful"
            results["Image Format"] = image.format
            results["Width"] = image.width
            results["Height"] = image.height
            results["Color Mode"] = image.mode

            try:
                exif_data = image.getexif()
                readable_exif = {}

                for tag_id, value in exif_data.items():
                    tag_name = TAGS.get(tag_id, str(tag_id))

                    if isinstance(value, bytes):
                        value = value.hex()

                    readable_exif[str(tag_name)] = str(value)

                # Some EXIF formats store additional camera details
                # in a nested IFD.
                try:
                    exif_ifd = exif_data.get_ifd(0x8769)

                    for tag_id, value in exif_ifd.items():
                        tag_name = TAGS.get(
                            tag_id, f"EXIF Tag {tag_id}"
                        )

                        if isinstance(value, bytes):
                            value = value.hex()

                        readable_exif[str(tag_name)] = str(value)

                except Exception:
                    pass

                results["EXIF Metadata"] = readable_exif

            except Exception:
                results["EXIF Metadata"] = {}

    except Exception:
        results["Analysis Status"] = (
            "Not a supported image or image could not be opened"
        )

    return results


def extract_text_artefacts(file_bytes):
    results = {
        "Analysis Status": "Not available",
        "Character Count": 0,
        "Email Addresses": [],
        "URLs": [],
        "IP Addresses": [],
        "Text Preview": ""
    }

    try:
        text_content = file_bytes.decode("utf-8-sig")
    except UnicodeDecodeError:
        try:
            text_content = file_bytes.decode("utf-8", errors="replace")
        except Exception:
            results["Analysis Status"] = "Unable to decode text"
            return results

    if "\x00" in text_content[:4096]:
        results["Analysis Status"] = (
            "Possible binary content; text analysis skipped"
        )
        return results

    results["Analysis Status"] = "Successful"
    results["Character Count"] = len(text_content)
    results["Text Preview"] = text_content[:2000]

    email_pattern = (
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
    )
    url_pattern = r"https?://[^\s<>\"']+"

    results["Email Addresses"] = sorted(
        set(re.findall(email_pattern, text_content))
    )

    results["URLs"] = sorted(
        set(re.findall(url_pattern, text_content))
    )

    candidate_pattern = (
        r"(?<![A-Za-z0-9])"
        r"(?:"
        r"(?:\d{1,3}\.){3}\d{1,3}"
        r"|"
        r"[0-9A-Fa-f:]{2,39}"
        r")"
        r"(?![A-Za-z0-9])"
    )

    valid_addresses = set()

    for candidate in re.findall(candidate_pattern, text_content):
        try:
            valid_addresses.add(str(ipaddress.ip_address(candidate)))
        except ValueError:
            continue

    results["IP Addresses"] = sorted(valid_addresses)

    return results


def build_artefact_report(filename, file_bytes):
    return {
        "Filename": filename,
        "File Size (bytes)": len(file_bytes),
        "File Extension": Path(filename).suffix.lower(),
        "SHA-256": calculate_hash(file_bytes),
        "Analysis Time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "File Signature Analysis": identify_file_signature(
            file_bytes, filename
        ),
        "Image Metadata": extract_image_metadata(file_bytes),
        "Text Artefacts": extract_text_artefacts(file_bytes),
        "Important Note": (
            "Automated findings require human verification. "
            "This report does not prove authenticity or malicious activity."
        )
    }


# ============================================================
# 5. NAVIGATION
# ============================================================

PAGES = [
    "Dashboard",
    "Evidence Integrity",
    "Disk Forensics",
    "File Signature Analysis",
    "Forensic Artefact Extraction",
    "Duplicate Evidence Detection",
    "Evidence Timeline",
    "Memory Forensics",
    "Investigation Report",
    "About Project"
]

if "page" not in st.session_state:
    st.session_state.page = "Dashboard"


def navigate_to(page):
    st.session_state.page = page
    st.session_state.sidebar_page = page


# ============================================================
# 6. STYLING
# ============================================================

st.markdown("""
<style>
.stApp {
    background-color: #f4f7fb;
}

[data-testid="stSidebar"] {
    background-color: #101b30;
}

[data-testid="stSidebar"] * {
    color: white;
}

.main-header {
    background: linear-gradient(120deg, #13213c, #244b78);
    padding: 28px;
    border-radius: 15px;
    margin-bottom: 22px;
    color: white;
}

.main-header h1 {
    color: white;
    font-size: 34px;
}

.main-header p {
    color: #d8e7ff;
}

.feature-card {
    background: white;
    padding: 17px;
    border-radius: 12px;
    border: 1px solid #e2e9f2;
    min-height: 125px;
}
</style>
""", unsafe_allow_html=True)


def show_header():
    st.markdown("""
    <div class="main-header">
        <h1>🔎 DFIR Explorer</h1>
        <p>Disk and Memory Forensic Artefact Extraction Framework</p>
    </div>
    """, unsafe_allow_html=True)


def show_heading(title, description):
    st.title(title)
    st.write(description)


show_header()


# ============================================================
# 7. SIDEBAR
# ============================================================

with st.sidebar:
    st.markdown("## 🔎 DFIR Explorer")
    st.caption("Digital Forensics Toolkit")
    st.divider()

    if "sidebar_page" not in st.session_state:
        st.session_state.sidebar_page = st.session_state.page

    st.radio(
        "NAVIGATION",
        PAGES,
        key="sidebar_page",
        on_change=lambda: setattr(
            st.session_state,
            "page",
            st.session_state.sidebar_page
        )
    )

    st.divider()
    st.caption("SYSTEM INFORMATION")
    st.write(f"Operating System: {platform.system()}")
    st.write(f"Python: {platform.python_version()}")


# ============================================================
# 8. DASHBOARD
# ============================================================

if st.session_state.page == "Dashboard":

    show_heading(
        "Investigation Dashboard",
        "A central workspace for exploring digital evidence "
        "and recording forensic checks."
    )

    records = get_records()

    integrity_records = sum(
        r["Category"] == "Evidence Integrity" for r in records
    )
    disk_records = sum(
        r["Category"] == "Disk Forensics" for r in records
    )
    memory_records = sum(
        r["Category"] == "Memory Forensics" for r in records
    )
    duplicate_records = sum(
        r["Category"] == "Duplicate Evidence Detection" for r in records
    )
    artefact_records = sum(
        r["Category"] == "Forensic Artefact Extraction" for r in records
    )

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Evidence Records", len(records))
    col2.metric("Integrity Checks", integrity_records)
    col3.metric("Disk Analyses", disk_records)
    col4.metric("Memory Records", memory_records)

    col1, col2 = st.columns(2)
    col1.metric("Duplicate Analysis Records", duplicate_records)
    col2.metric("Artefact Extraction Records", artefact_records)

    st.markdown("### Forensic Tools")

    tools = [
        ("🔐 Evidence Integrity", "Calculate and compare SHA-256 hashes.",
         "Evidence Integrity"),
        ("💽 Disk Forensics", "Inspect basic properties of uploaded files.",
         "Disk Forensics"),
        ("🧩 File Signature Analysis", "Inspect supported file signatures.",
         "File Signature Analysis"),
        ("🔬 Artefact Extraction", "Extract supported image and text artefacts.",
         "Forensic Artefact Extraction"),
        ("🔎 Duplicate Detection", "Compare hashes against saved records.",
         "Duplicate Evidence Detection"),
        ("🧠 Memory Forensics", "Record memory files and investigation notes.",
         "Memory Forensics"),
        ("📊 Investigation Report", "Review and export saved records.",
         "Investigation Report"),
        ("🕒 Evidence Timeline", "Search and sort saved evidence.",
         "Evidence Timeline")
    ]

    for start in range(0, len(tools), 3):
        cols = st.columns(3)

        for col, tool in zip(cols, tools[start:start + 3]):
            title, description, page = tool

            with col:
                st.markdown(
                    f"<div class='feature-card'><h3>{title}</h3>"
                    f"<p>{description}</p></div>",
                    unsafe_allow_html=True
                )

                st.button(
                    f"Open {page}",
                    key=f"open_{page}",
                    use_container_width=True,
                    on_click=navigate_to,
                    args=(page,)
                )

    st.markdown("### Recent Evidence")

    if records:
        for record in records[:5]:
            with st.container(border=True):
                st.write(f"**{record['Filename']}**")
                st.caption(
                    f"{record['Category']} · {record['Date and Time']}"
                )
                st.code(record["SHA-256"], language=None)
    else:
        st.info("No evidence records have been saved yet.")


# ============================================================
# 9. EVIDENCE INTEGRITY
# ============================================================

elif st.session_state.page == "Evidence Integrity":

    show_heading(
        "Evidence Integrity Verification",
        "Calculate SHA-256 and compare it with a known hash."
    )

    st.info(
        "SHA-256 creates a digital fingerprint of file contents. "
        "Matching hashes indicate matching contents."
    )

    uploaded_file = st.file_uploader(
        "Upload a file", key="integrity_upload"
    )

    if uploaded_file:
        file_bytes = uploaded_file.getvalue()
        file_hash = calculate_hash(file_bytes)

        st.write(f"Filename: {uploaded_file.name}")
        st.write(f"File size: {len(file_bytes):,} bytes")
        st.markdown("### SHA-256")
        st.code(file_hash, language=None)

        if st.button("Save Evidence Integrity Record"):
            if save_record(
                uploaded_file.name, file_bytes,
                "Evidence Integrity", "SHA-256 calculated"
            ):
                st.success("Evidence record saved.")
            else:
                st.warning("This file is already recorded in this category.")

        expected_hash = st.text_input("Enter the expected SHA-256 hash").strip()

        if st.button("Verify Hash"):
            if len(expected_hash) != 64 or any(
                c not in "0123456789abcdefABCDEF" for c in expected_hash
            ):
                st.error("Enter a valid 64-character hexadecimal SHA-256 hash.")
            elif file_hash.lower() == expected_hash.lower():
                st.success("MATCH: Both hashes are identical.")
            else:
                st.error("MISMATCH: The hashes are different.")


# ============================================================
# 10. DISK FORENSICS
# ============================================================

elif st.session_state.page == "Disk Forensics":

    show_heading(
        "Disk Forensics",
        "Inspect an uploaded file and record its digital fingerprint."
    )

    st.warning(
        "This prototype examines uploaded files. It does not image an entire disk."
    )

    uploaded_file = st.file_uploader(
        "Choose a file for inspection", key="disk_upload"
    )

    if uploaded_file:
        file_bytes = uploaded_file.getvalue()
        file_hash = calculate_hash(file_bytes)

        st.markdown("### File Information")
        st.write(f"Filename: {uploaded_file.name}")
        st.write(f"Size: {len(file_bytes):,} bytes")
        st.write(f"Extension: {Path(uploaded_file.name).suffix or 'None'}")
        st.write(f"Operating system: {platform.system()}")
        st.write(f"Inspection time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        st.markdown("### SHA-256")
        st.code(file_hash, language=None)

        image_info = extract_image_metadata(file_bytes)

        if image_info["Analysis Status"] == "Successful":
            st.markdown("### Image Information")
            st.write(f"Format: {image_info['Image Format']}")
            st.write(
                f"Dimensions: {image_info['Width']} × {image_info['Height']}"
            )
            st.write(f"Color mode: {image_info['Color Mode']}")

            with st.expander("View image"):
                st.image(file_bytes, use_container_width=True)

        if st.button("Save Disk Forensics Record"):
            if save_record(
                uploaded_file.name, file_bytes,
                "Disk Forensics", "Basic file metadata inspected"
            ):
                st.success("Disk forensics record saved.")
            else:
                st.warning("This file is already recorded in this category.")


# ============================================================
# 11. FILE SIGNATURE ANALYSIS
# ============================================================

elif st.session_state.page == "File Signature Analysis":

    show_heading(
        "File Signature Analysis",
        "Identify common file signatures and compare extensions."
    )

    st.info(
        "A signature match does not prove that a file is safe or authentic."
    )

    signature_file = st.file_uploader(
        "Upload a file to analyze", key="signature_upload"
    )

    if signature_file:
        file_bytes = signature_file.getvalue()
        result = identify_file_signature(file_bytes, signature_file.name)

        st.write(f"Filename: {signature_file.name}")
        st.write(f"Size: {len(file_bytes):,} bytes")
        st.write(f"Detected type: {result['Detected Type']}")
        st.write(f"Extension: {result['Extension']}")
        st.write(f"Result: {result['Result']}")
        st.write(result["Description"])

        st.markdown("### SHA-256")
        st.code(calculate_hash(file_bytes), language=None)

        if result["Result"] == "MATCH":
            st.success("Signature and extension are consistent.")
        elif result["Result"] == "POSSIBLE MISMATCH":
            st.error("Possible mismatch. Further examination is recommended.")
        else:
            st.warning("The file format was not definitively identified.")

        with st.expander("View first 32 bytes in hexadecimal"):
            st.code(file_bytes[:32].hex(" "), language=None)

        if st.button("Save File Signature Analysis Record"):
            details = (
                f"Detected type: {result['Detected Type']}; "
                f"Result: {result['Result']}; "
                f"Extension: {result['Extension']}"
            )

            if save_record(
                signature_file.name, file_bytes,
                "File Signature Analysis", details
            ):
                st.success("Signature analysis record saved.")
            else:
                st.warning("This file is already recorded in this category.")

    st.markdown("### Supported File Types")
    st.write(
        "PNG, JPEG, GIF, BMP, PDF, ZIP-based files, RAR, 7-Zip, GZIP, "
        "ELF, Windows executable-family files, SQLite, WAV, MP3, "
        "MP4/QuickTime, and older Microsoft Office containers."
    )


# ============================================================
# 12. FORENSIC ARTEFACT EXTRACTION
# ============================================================

elif st.session_state.page == "Forensic Artefact Extraction":

    show_heading(
        "Forensic Artefact Extraction",
        "Extract supported metadata and text-based artefacts from a file."
    )

    st.warning(
        "Use only files you are authorized to examine. "
        "Automated results are leads for further examination, not proof of wrongdoing."
    )

    st.markdown("### Upload Evidence")

    artefact_file = st.file_uploader(
        "Choose an image or text file",
        key="artefact_upload"
    )

    if artefact_file:
        file_bytes = artefact_file.getvalue()

        with st.spinner("Examining uploaded file..."):
            report = build_artefact_report(
                artefact_file.name, file_bytes
            )

        st.success("File examination completed.")

        col1, col2, col3 = st.columns(3)
        col1.metric("File Size", f"{len(file_bytes):,} bytes")
        col2.metric(
            "Image Dimensions",
            (
                f"{report['Image Metadata']['Width']} × "
                f"{report['Image Metadata']['Height']}"
                if report["Image Metadata"]["Analysis Status"] == "Successful"
                else "Not applicable"
            )
        )
        col3.metric(
            "Email Candidates",
            len(report["Text Artefacts"]["Email Addresses"])
        )

        st.markdown("### 1. File Information")

        file_info = {
            "Filename": report["Filename"],
            "File Size (bytes)": report["File Size (bytes)"],
            "Extension": report["File Extension"] or "No extension",
            "Detected Type": report["File Signature Analysis"]["Detected Type"],
            "Signature Result": report["File Signature Analysis"]["Result"],
            "Analysis Time": report["Analysis Time"]
        }

        st.dataframe(
            [{"Property": k, "Value": str(v)} for k, v in file_info.items()],
            use_container_width=True,
            hide_index=True
        )

        st.markdown("### 2. SHA-256 Hash")
        st.code(report["SHA-256"], language=None)

        st.markdown("### 3. Image Metadata")

        image_data = report["Image Metadata"]

        if image_data["Analysis Status"] == "Successful":
            st.write(f"**Format:** {image_data['Image Format']}")
            st.write(f"**Width:** {image_data['Width']} pixels")
            st.write(f"**Height:** {image_data['Height']} pixels")
            st.write(f"**Color mode:** {image_data['Color Mode']}")

            exif_data = image_data["EXIF Metadata"]

            if exif_data:
                st.markdown("#### Available EXIF Metadata")
                st.dataframe(
                    [
                        {"Metadata Field": key, "Value": value}
                        for key, value in exif_data.items()
                    ],
                    use_container_width=True,
                    hide_index=True
                )

                capture_date = (
                    exif_data.get("DateTimeOriginal")
                    or exif_data.get("DateTimeDigitized")
                    or exif_data.get("DateTime")
                )

                if capture_date:
                    st.info(
                        f"Capture date recorded in metadata: {capture_date}"
                    )
            else:
                st.info(
                    "No readable EXIF metadata was found. "
                    "This is common and does not itself indicate tampering."
                )

            with st.expander("Preview image"):
                st.image(file_bytes, use_container_width=True)

        else:
            st.info(
                "This file could not be opened as a supported image. "
                "Image metadata is not available."
            )

        st.markdown("### 4. Text Artefact Extraction")

        text_data = report["Text Artefacts"]

        if text_data["Analysis Status"] == "Successful":
            st.write(
                f"**Character count:** {text_data['Character Count']:,}"
            )

            for label, key in [
                ("Email address candidates", "Email Addresses"),
                ("URL candidates", "URLs"),
                ("Valid IP address candidates", "IP Addresses")
            ]:
                with st.expander(
                    f"{label} ({len(text_data[key])})"
                ):
                    if text_data[key]:
                        for item in text_data[key]:
                            st.write(f"- {item}")
                    else:
                        st.write("No matches found.")

            with st.expander("View extracted text preview"):
                st.text(text_data["Text Preview"] or "(No text found)")

        else:
            st.info(text_data["Analysis Status"])

        st.markdown("### 5. File Signature Interpretation")
        signature_data = report["File Signature Analysis"]

        st.write(f"**Detected type:** {signature_data['Detected Type']}")
        st.write(f"**Result:** {signature_data['Result']}")
        st.write(signature_data["Description"])

        st.markdown("### 6. Export Findings")

        json_data = json.dumps(report, indent=4, ensure_ascii=False)

        st.download_button(
            "Download Full Forensic Report (JSON)",
            data=json_data.encode("utf-8"),
            file_name="dfir_artefact_report.json",
            mime="application/json",
            use_container_width=True
        )

        csv_rows = []

        for key, value in file_info.items():
            csv_rows.append({
                "Section": "File Information",
                "Finding": key,
                "Value": str(value)
            })

        for key, value in image_data.items():
            if key == "EXIF Metadata":
                for exif_key, exif_value in value.items():
                    csv_rows.append({
                        "Section": "EXIF Metadata",
                        "Finding": exif_key,
                        "Value": str(exif_value)
                    })
            else:
                csv_rows.append({
                    "Section": "Image Metadata",
                    "Finding": key,
                    "Value": str(value)
                })

        for key in [
            "Email Addresses", "URLs", "IP Addresses"
        ]:
            csv_rows.append({
                "Section": "Text Artefacts",
                "Finding": key,
                "Value": "; ".join(text_data[key])
            })

        csv_buffer = io.StringIO()
        writer = csv.DictWriter(
            csv_buffer,
            fieldnames=["Section", "Finding", "Value"]
        )
        writer.writeheader()
        writer.writerows(csv_rows)

        st.download_button(
            "Download Findings (CSV)",
            data=csv_buffer.getvalue().encode("utf-8"),
            file_name="dfir_artefact_findings.csv",
            mime="text/csv",
            use_container_width=True
        )

        st.markdown("### 7. Save Investigation Record")

        notes = st.text_area(
            "Investigation notes (optional)",
            key="artefact_notes",
            placeholder="Describe the purpose of the examination..."
        )

        if st.button("Save Artefact Extraction Record"):
            summary = (
                f"Detected type: {signature_data['Detected Type']}; "
                f"Image analysis: {image_data['Analysis Status']}; "
                f"Text analysis: {text_data['Analysis Status']}; "
                f"Email candidates: {len(text_data['Email Addresses'])}; "
                f"URLs: {len(text_data['URLs'])}; "
                f"IP candidates: {len(text_data['IP Addresses'])}; "
                f"Notes: {notes}"
            )

            if save_record(
                artefact_file.name,
                file_bytes,
                "Forensic Artefact Extraction",
                summary
            ):
                st.success("Artefact extraction record saved.")
            else:
                st.warning(
                    "A record with this file hash and category already exists."
                )

        st.caption(
            "The application saves the file hash and investigation summary "
            "in SQLite. It does not store a copy of the uploaded file."
        )


# ============================================================
# 13. DUPLICATE EVIDENCE DETECTION
# ============================================================

elif st.session_state.page == "Duplicate Evidence Detection":

    show_heading(
        "Duplicate Evidence Detection",
        "Compare an uploaded file against previously recorded hashes."
    )

    duplicate_file = st.file_uploader(
        "Upload a file to check for duplicates",
        key="duplicate_detection_upload"
    )

    if duplicate_file:
        file_bytes = duplicate_file.getvalue()
        file_hash = calculate_hash(file_bytes)
        records = get_records()

        matching_records = [
            record for record in records
            if record["SHA-256"].lower() == file_hash.lower()
        ]

        st.write(f"Filename: {duplicate_file.name}")
        st.write(f"File size: {len(file_bytes):,} bytes")
        st.code(file_hash, language=None)

        if matching_records:
            st.error("Matching evidence record(s) found.")
            st.dataframe(
                matching_records,
                use_container_width=True,
                hide_index=True
            )
        else:
            st.success(
                "No matching hash was found in the current database."
            )

        if st.button("Save Duplicate Detection Record"):
            details = (
                f"Matching records found: {len(matching_records)}; "
                f"Result: {'MATCH FOUND' if matching_records else 'NO MATCH FOUND'}"
            )

            if save_record(
                duplicate_file.name, file_bytes,
                "Duplicate Evidence Detection", details
            ):
                st.success("Duplicate detection record saved.")
            else:
                st.warning("This file is already recorded in this category.")


# ============================================================
# 14. MEMORY FORENSICS
# ============================================================

elif st.session_state.page == "Memory Forensics":

    show_heading(
        "Memory Forensics",
        "Record a memory-analysis file and document observations."
    )

    st.warning(
        "This page does not acquire live RAM or parse memory images."
    )

    st.markdown("""
    ### Suggested Workflow

    1. Obtain a memory image through an authorized acquisition process.
    2. Preserve the original image.
    3. Calculate a hash to help verify its integrity.
    4. Analyze it using an appropriate memory-forensics tool.
    5. Record findings and document the investigation.
    """)

    memory_file = st.file_uploader(
        "Upload a memory image or analysis file",
        key="memory_upload"
    )

    if memory_file:
        memory_bytes = memory_file.getvalue()
        memory_hash = calculate_hash(memory_bytes)

        st.write(f"Filename: {memory_file.name}")
        st.write(f"Size: {len(memory_bytes):,} bytes")
        st.code(memory_hash, language=None)

        notes = st.text_area(
            "Analysis notes",
            placeholder="Record the source and observations..."
        )

        if st.button("Save Memory Forensics Record"):
            if save_record(
                memory_file.name, memory_bytes,
                "Memory Forensics", notes
            ):
                st.success("Memory forensics record saved.")
            else:
                st.warning("This file is already recorded in this category.")


# ============================================================
# 15. INVESTIGATION REPORT
# ============================================================

elif st.session_state.page == "Investigation Report":

    show_heading(
        "Investigation Report",
        "Review and export saved evidence records."
    )

    st.caption(
        "The database stores evidence metadata and hashes, not original files."
    )

    records = get_records()

    if records:
        st.dataframe(
            records,
            use_container_width=True,
            hide_index=True
        )

        fields = [
            "Filename", "Category", "SHA-256",
            "Size (bytes)", "Date and Time", "Details"
        ]

        csv_buffer = io.StringIO()
        writer = csv.DictWriter(
            csv_buffer,
            fieldnames=fields,
            extrasaction="ignore"
        )
        writer.writeheader()
        writer.writerows(records)

        st.download_button(
            "Download Investigation Report (CSV)",
            data=csv_buffer.getvalue().encode("utf-8"),
            file_name="dfir_investigation_report.csv",
            mime="text/csv",
            use_container_width=True
        )

        text_report = [
            "DFIR EXPLORER — INVESTIGATION REPORT",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Total records: {len(records)}",
            ""
        ]

        for index, record in enumerate(records, start=1):
            text_report.extend([
                f"Record {index}",
                f"Filename: {record['Filename']}",
                f"Category: {record['Category']}",
                f"SHA-256: {record['SHA-256']}",
                f"Size: {record['Size (bytes)']} bytes",
                f"Date: {record['Date and Time']}",
                f"Details: {record['Details']}",
                ""
            ])

        st.download_button(
            "Download Investigation Report (TXT)",
            data="\n".join(text_report),
            file_name="dfir_investigation_report.txt",
            mime="text/plain",
            use_container_width=True
        )

        st.divider()
        st.warning(
            "Clearing records permanently deletes evidence metadata "
            "from the local database. Original files are not deleted."
        )

        confirm_clear = st.checkbox(
            "I understand that this permanently deletes all database records."
        )

        if st.button(
            "Clear All Evidence Records",
            disabled=not confirm_clear
        ):
            clear_records()
            st.success("All evidence records have been cleared.")
            st.rerun()

    else:
        st.info(
            "No evidence records are saved yet. Save a record from "
            "a forensic section to create a report."
        )


# ============================================================
# 16. EVIDENCE TIMELINE
# ============================================================

elif st.session_state.page == "Evidence Timeline":

    show_heading(
        "Evidence Timeline",
        "Explore saved records in chronological order."
    )

    st.info(
        "The timeline shows when a record was saved in this application, "
        "not the original creation time of the file."
    )

    records = get_records()

    if records:
        col1, col2 = st.columns(2)

        with col1:
            search_filename = st.text_input(
                "Search by filename",
                placeholder="Enter a filename..."
            )

        categories = sorted({
            record["Category"] for record in records
        })

        with col2:
            selected_category = st.selectbox(
                "Filter by category",
                ["All Categories"] + categories
            )

        sort_order = st.radio(
            "Timeline order",
            ["Newest First", "Oldest First"],
            horizontal=True
        )

        filtered_records = records.copy()

        if search_filename.strip():
            filtered_records = [
                record for record in filtered_records
                if search_filename.strip().lower()
                in record["Filename"].lower()
            ]

        if selected_category != "All Categories":
            filtered_records = [
                record for record in filtered_records
                if record["Category"] == selected_category
            ]

        filtered_records.sort(
            key=lambda record: record["Date and Time"],
            reverse=(sort_order == "Newest First")
        )

        st.metric("Matching Evidence Records", len(filtered_records))

        for index, record in enumerate(filtered_records, start=1):
            with st.container(border=True):
                st.markdown(f"### {index}. {record['Filename']}")
                st.caption(f"Recorded on: {record['Date and Time']}")
                st.write(f"**Category:** {record['Category']}")
                st.write(f"**Size:** {record['Size (bytes)']:,} bytes")
                st.code(record["SHA-256"], language=None)

                if record["Details"]:
                    st.write(f"**Notes:** {record['Details']}")

        if not filtered_records:
            st.warning("No records match your filters.")

    else:
        st.info("No evidence records are available yet.")


# ============================================================
# 17. ABOUT PROJECT
# ============================================================

elif st.session_state.page == "About Project":

    show_heading(
        "About DFIR Explorer",
        "An educational prototype demonstrating selected forensic workflows."
    )

    st.markdown("### Project Overview")

    st.write(
        "DFIR Explorer demonstrates file hashing, file-signature checks, "
        "basic file inspection, image metadata extraction, EXIF inspection, "
        "text artefact detection, duplicate hash checking, evidence records, "
        "a timeline, and report exports."
    )

    st.markdown("### Technologies Used")

    st.markdown("""
    - Python
    - Streamlit
    - SQLite
    - hashlib
    - Pillow
    - Python regular expressions
    - JSON and CSV
    """)

    st.markdown("### Current Limitations")

    st.markdown("""
    - Does not image a physical disk.
    - Does not recover deleted files.
    - Does not acquire live RAM or parse memory images.
    - Does not perform a malware scan.
    - Extracted email addresses, URLs, and IP addresses are only candidates.
    - Metadata may be missing, modified, or inaccurate.
    - File signatures do not prove that a file is safe or authentic.
    - Stores evidence metadata, not copies of the uploaded files.
    - Does not implement a complete chain-of-custody process.
    """)

    st.success(
        "Project objective: demonstrate selected forensic workflows "
        "through a beginner-friendly interface."
    )


# ============================================================
# 18. FOOTER
# ============================================================

st.divider()

st.caption(
    "DFIR Explorer | Academic Demonstration Prototype | "
    "Use only with files you are authorized to examine."
)