import logging
import tarfile
from pathlib import Path
from scanner.common.logging_config import configure_logging

logger = logging.getLogger(__name__)

EXCLUDED_SUFFIXES = {".tar.gz", ".gz", ".zip"}


# gets path, compresses that file and then deletes it.
def compressor(input_file: str | Path):
    input_file = Path(input_file)
    logger.debug(f"compressing {input_file}.")

    compressed_path = input_file.with_suffix(input_file.suffix + ".tar.gz")

    with tarfile.open(compressed_path, "w:gz") as tar:
        tar.add(input_file, arcname=input_file.name)

    input_file.unlink()


# checks all files in directory and selects all that are not excluded or defined compressed (EXCLUDED_SUFFIXES).
def compress_files(root: str | Path, exclude: str | Path):
    root = Path(root).resolve()
    exclude = Path(exclude).resolve()
    logger.debug(f"compressing files in {root}. excluding {exclude}.")

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if path == exclude:
            continue
        if path.suffix in EXCLUDED_SUFFIXES:
            continue
        else:
            compressor(path)


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
