import argparse
import os
import time
from pathlib import Path

import api
import json
from api import hash_it, vt_get_data, vt_post_files, vt_get_analyses, vt_get_upload_url, VT_FILE_NOT_AVAILABLE
from buffer import CSVBuffer, JSONBuffer, STDOUTBuffer

API_KEY = ""

JSON_FOLDER = 'json'


def get_json_path(filename, f_hash):
    file_name = f'{filename}-{f_hash}.json'
    json_folder_path = os.path.join(os.getcwd(), JSON_FOLDER)
    file_path = os.path.join(json_folder_path, file_name)
    return file_path


def is_already_scanned(filename, f_hash):
    return os.path.isfile(get_json_path(filename, f_hash))


NEW = 1
SCANNED = 2


def scan(filename, buffer):
    file = Path(filename)

    if not file.exists():
        raise Exception("File not found")

    file_hash = hash_it(file, "sha256")
    json_path = get_json_path(file.name, file_hash)
    if is_already_scanned(file.name, file_hash):
        with open(json_path, 'r') as json_file:
            json_obj = json.load(json_file)
            json_obj["filename"] = file.name
            json_obj["path"] = file
            buffer.append(json_obj)
        return SCANNED
    else:
        response = vt_get_data(file_hash)

        if response.status_code == VT_FILE_NOT_AVAILABLE:

            # The response of vt_post_files can only be parsed by vt_get_analysis.
            # vt_post_files and vt_get_analyses should be made into a single function,
            # but I left the separate in case there is a need to call vt_get_analysis
            # separately

            if file.stat().st_size > 32000000:  # 32MB
                response = vt_get_data(vt_get_analyses(
                    vt_post_files(file, vt_get_upload_url())))
            else:
                # for small files
                response = vt_get_data(vt_get_analyses(vt_post_files(file)))

        if response.status_code == 200:
            json_obj = response.json().get("data").get("attributes")
            json_obj["filename"] = file.name
            json_obj["path"] = str(file)
            buffer.append(json_obj)
            with open(json_path, 'w') as file:
                json.dump(json_obj, file, indent=4)
        else:
            raise Exception(response.status_code)
        return NEW


def batch_scan(paths, buffer):
    for path in paths:
        if scan(path, buffer) == NEW:
            time.sleep(15)


OUTPUT_FORMATS = dict(stdout=STDOUTBuffer, json=JSONBuffer, csv=CSVBuffer)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="scan your files with virustotal")
    parser.add_argument('--api_key', type=str, help='virustotal api key', required=True)
    parser.add_argument('--timeout', type=str, help='timeout between requests (default 15 == 15 seconds)', default="15")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--file', type=str, help='a file to scan', default=None)
    group.add_argument('--folder', type=str, help='a folder to scan recursively', default=None)
    group.add_argument('--list', type=str, help='a txt-list of files to scan', default=None)

    parser.add_argument('--output_format', type=str, help='output format', required=False)
    parser.add_argument('--output_path', type=str, help='output file', required=False)

    args = parser.parse_args()

    buffer = STDOUTBuffer()
    if args.output_format and args.output_format in OUTPUT_FORMATS:
        if args.output_format == 'json':
            buffer = JSONBuffer()
        if args.output_format == 'csv':
            buffer = CSVBuffer()

    if not isinstance(buffer, STDOUTBuffer) and not args.output_path:
        parser.error("--output_format requires --output_path")

    args = parser.parse_args()

    if args.api_key:
        API_KEY = args.api_key
        api.HEADERS = {"x-apikey": API_KEY}
    else:
        print("No api key received")

    if not os.path.exists(JSON_FOLDER):
        os.makedirs(JSON_FOLDER)

    if args.file:
        if os.path.isfile(args.file):
            scan(args.file, buffer)
        else:
            print(f'{args.file} is not a valid file path')
    elif args.folder:
        paths = []  # start with an empty list
        for dirpath, dirnames, filenames in os.walk(args.folder):
            for file in filenames:
                if file.endswith(".DS_Store"):
                    continue
                paths.append(os.path.join(dirpath, file))
        batch_scan(paths, buffer)
    elif args.list:
        with open(args.list, 'r') as file:
            paths = [line.strip() for line in file.readlines()]
        valid_path = True
        for path in paths:
            if not os.path.isfile(path):
                print(f'{path} is not a valid file path')
                valid_path = False
        if valid_path:
            batch_scan(paths, buffer)
        else:
            print('fix file paths to start scan')
    else:
        print("No files received.")

    if not isinstance(buffer, STDOUTBuffer):
        with open(args.output_path, 'w') as file:
            file.write(buffer.flush())
