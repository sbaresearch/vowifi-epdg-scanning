import datetime
import os
import subprocess
import logging
from pathlib import Path
from scanner.common.logging_config import configure_logging

logger = logging.getLogger(__name__)


# run zdns with generated ePDGs.
def zdns_runner(config_path: Path, input_path: Path, output_path: Path):
    logger.info("running zdns scan...")

    config_file = config_path / "zdns_config.ini"
    input_file = input_path / "epdg_domains_generated.txt"
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_file = output_path / f"epdg_dns_scan_{timestamp}.json"

    zdns = (
        "zdns",
        "MULTIPLE",
        "-c",
        str(config_file),
        "--input-file",
        str(input_file),
        "--output-file",
        str(output_file),
    )

    logger.debug("starting zdns subprocess.")
    try:
        subprocess.run(
            zdns,
            # shell=True,
            check=True,
        )
        logger.info("zdns scan finished...")
    except subprocess.CalledProcessError as e:
        logger.error("zdns scan failed with return code %s", e.returncode)
        raise
    except FileNotFoundError:
        logger.error("zdns executable not found. Please ensure it is installed and in your PATH.")
        raise


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    
    default_base_dir = Path(__file__).resolve().parent.parent
    data_dir = Path(os.getenv("DATA_DIR", default_base_dir / "data"))
    zdns_runner(data_dir / "config", data_dir / "generated", data_dir / "scans" / "raw")
