import datetime
import subprocess
import logging
from scanner.common.logging_config import configure_logging

logger = logging.getLogger(__name__)


# run zdns with generated ePDGs.
def zdns_runner(config_path, input_path, output_path):
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
    zdns_result = subprocess.run(
        zdns,
        # shell=True,
        check=True,
    )

    logger.info("zdns scan finished...")


if __name__ == "__main__":
    configure_logging("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    zdns_runner()
