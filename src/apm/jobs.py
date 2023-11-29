""" need to refactor this into better parts...
"""

import logging
import json

import yaml
import os

logger = logging.getLogger(__name__)
# logger.setLevel(logging.DEBUG)

# sh = logging.StreamHandler()
# formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
# sh.setFormatter(formatter)
# logger.addHandler(sh)


def parse_yaml(filename: str):
    """Read yaml file so we get a dict that can be worked with"""

    output = {}
    with open(filename, encoding="UTF-8") as job_file:
        output = yaml.safe_load(job_file)
    return output


def get_jobs(jobs_directory: str, job_prefix: str):
    # Parse out job definitions
    job_dir = "job_definitions"
    job_files = os.listdir(jobs_directory)

    logger.debug("Job files found: %s", job_files)

    job_definitions = {}

    for file in job_files:
        job_name = job_prefix + file.split(sep=".")[0]
        job_definitions[job_name] = parse_yaml(f"{job_dir}/{file}")

    return job_definitions
