#!/usr/bin/env python3
"""
Script to fetch the latest CWE data from MITRE.

This script downloads the latest CWE XML data, unzips it to the knowledge directory,
and also downloads the XSD schema for validation purposes.
"""

import os
import sys
import requests
import zipfile
from pathlib import Path
import logging
from io import BytesIO
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("fetch_cwe_data")

# URLs for CWE data
CWE_XML_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CWE_XSD_URL = "https://cwe.mitre.org/data/xsd/cwe_schema_latest.xsd"

# Directories
SCRIPT_DIR = Path(__file__).parent.absolute()
REPO_ROOT = SCRIPT_DIR.parent
DATA_DIR = REPO_ROOT / "data"
KNOWLEDGE_DIR = DATA_DIR / "knowledge"
CWE_DIR = KNOWLEDGE_DIR / "cwe"


def ensure_directories():
    """Ensure required directories exist."""
    for directory in [DATA_DIR, KNOWLEDGE_DIR, CWE_DIR]:
        directory.mkdir(parents=True, exist_ok=True)
        logger.info(f"Ensured directory exists: {directory}")


def download_file(url, local_filename=None):
    """Download file from URL and return the content.

    Args:
        url: URL to download from
        local_filename: Optional filename to save the downloaded content

    Returns:
        If local_filename is provided, returns the path to the file.
        Otherwise, returns the content as bytes.
    """
    logger.info(f"Downloading {url}")
    try:
        response = requests.get(url, stream=True)
        response.raise_for_status()

        if local_filename:
            with open(local_filename, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
            logger.info(f"Downloaded to {local_filename}")
            return local_filename
        else:
            return response.content
    except requests.exceptions.RequestException as e:
        logger.error(f"Error downloading {url}: {e}")
        raise


def process_cwe_zip(zip_content):
    """Process the CWE ZIP file and extract its contents.

    Args:
        zip_content: ZIP file content as bytes
    """
    try:
        with zipfile.ZipFile(BytesIO(zip_content)) as zip_ref:
            # Get a timestamp for versioning
            timestamp = datetime.now().strftime("%Y%m%d")

            # Extract all files to the CWE directory
            zip_ref.extractall(CWE_DIR)
            logger.info(f"Extracted CWE data to {CWE_DIR}")

            # Also save a timestamped copy of the XML
            xml_files = [f for f in zip_ref.namelist() if f.endswith(".xml")]
            if xml_files:
                for xml_file in xml_files:
                    content = zip_ref.read(xml_file)
                    versioned_file = CWE_DIR / f"cwec_{timestamp}.xml"
                    with open(versioned_file, "wb") as f:
                        f.write(content)
                    logger.info(f"Saved timestamped copy to {versioned_file}")
    except zipfile.BadZipFile:
        logger.error("The downloaded file is not a valid ZIP file")
        raise


def main():
    """Main function to fetch CWE data."""
    try:
        # Ensure directories exist
        ensure_directories()

        # Download CWE XML ZIP
        logger.info("Downloading CWE XML data...")
        zip_content = download_file(CWE_XML_URL)
        process_cwe_zip(zip_content)

        # Download CWE XSD schema
        logger.info("Downloading CWE XSD schema...")
        xsd_path = CWE_DIR / "cwe_schema_latest.xsd"
        download_file(CWE_XSD_URL, xsd_path)

        logger.info("Successfully downloaded and processed CWE data!")
        return 0

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
