#!/usr/bin/env python3
import os
import logging
import argparse
import webbrowser


_LOGGER = logging.getLogger()

def generate_cov_report(open_report: bool):
    logging.basicConfig(level=logging.INFO)
    os.environ["RUSTFLAGS"] = "-Cinstrument-coverage"
    os.environ["LLVM_PROFILE_FILE"] = "target/coverage/%p-%m.profraw"
    _LOGGER.info("Executing tests with coverage")
    os.system("cargo test")
    os.system(
        "grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing "
        "-o ./target/debug/coverage/"
    )
    if open_report:
        coverage_report_path = os.path.abspath("./target/debug/coverage/index.html")
        webbrowser.open_new_tab(coverage_report_path)
    _LOGGER.info("Done")


def main():
    parser = argparse.ArgumentParser(
        description="Generate coverage report and optionally open it in a browser"
    )
    parser.add_argument(
        "--open", action="store_true", help="Open the coverage report in a browser"
    )
    args = parser.parse_args()
    generate_cov_report(args.open)


if __name__ == "__main__":
    main()
