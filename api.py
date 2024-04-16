import hashlib
from time import sleep

import requests

from parser import get_parsed_data_csv as get_parsed_data


def hash_it(file, algorithm):
    '''
    Returns hash of the file provided

    :param file: file to hash (type: str/pathlib obj) :param algorithm: algorithm to
    to use for hashing (valid algorithms: sha1 | sha256 | md5) (type: str)
    :return: file hash (type: str)
    '''
    if algorithm == "sha256":
        hasher = hashlib.sha256()
    elif algorithm == "sha1":
        hasher = hashlib.sha1()
    elif algorithm == "md5":
        hasher = hashlib.md5()
    else:
        raise Exception(
            "Incompatible hash algorithm used. Choose from: sha256 | sha1 | md5")

    with open(file, 'rb') as f:
        hasher.update(f.read())
    return hasher.hexdigest()


def vt_get_data(f_hash):
    '''
    The function gets the data against the file hash provided
    from the virustotal api

    :param f_hash: sha256 of the file to scan with virustotal
    :return: requests.models.Response
    '''
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response


def vt_post_files(file, url="https://www.virustotal.com/api/v3/files"):
    '''
    The function uploads a file to virustotal
    for analysis and returns the response from the
    virustotal api

    :param file: file to upload for analysis :param url: url to upload
    file to (use for files larger than 32MB) :return: requests.models.Response
    '''
    with open(file, "rb") as f:
        file_bin = f.read()
    print("UPLOADING")
    upload_package = {"file": (file.name, file_bin)}
    while True:
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if error_handle(response):
            break
    return response


def vt_get_analyses(response):
    '''
    The function returns the file hash of the uploaded file
    once the analysis of the uploaded file is available

    :param response: requests.models.Response
    :return: sha256 of the previously uploaded file (type: str)
    '''
    _id = response.json().get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    print(f"ID: {_id}")
    while True:
        print("WAITING FOR ANALYSIS REPORT")
        sleep(60)
        while True:
            response = requests.get(url, headers=HEADERS)
            if error_handle(response):
                break
        if response.json().get("data").get("attributes").get("status") == "completed":
            f_hash = response.json().get("meta").get("file_info").get("sha256")
            return f_hash


def vt_get_upload_url():
    '''
    The function returns a url to upload files larger than 32MB
    to the virustotal api
    '''
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    while True:
        response = requests.get(url, headers=HEADERS)
        if error_handle(response):
            break
    return response.json()["data"]


def error_handle(response):
    '''
    The function returns True if there are no errors
    and returns False otherwise

    :param response: requests.models.Response
    :return: bool
    '''
    if response.status_code == 429:
        print("WAITING")
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True


def parse_response(response):
    '''
    The function extracts useful information from the respose JSON file
    and return it in JSON format.

    :param response: requests.models.Response
    :return: parsed data as json/dict
    '''
    json_obj = response.json().get("data").get("attributes")
    return get_parsed_data(json_obj)


VT_FILE_NOT_AVAILABLE = 404
HEADERS = {}
