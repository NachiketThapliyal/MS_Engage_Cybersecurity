import hashlib
import argparse
from time import sleep
from pathlib import Path
from pprint import pprint
import requests

try:
    from key import API_KEY
except:
    API_KEY = "e2dec92fb07bd5aca4a00f5dfdcfaa8ff14880d6ca596118f3caf7fc4c77869e"


HEADERS = {"x-apikey": API_KEY}


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


def getData(f_hash):
   
   #getting data
    url = f"https://www.virustotal.com/api/v3/files/{f_hash}"
    while True:
        response = requests.get(url, headers=HEADERS)
        if handleError(response):
            break
    return response


def postFiles(file, url="https://www.virustotal.com/api/v3/files"):
  
    #upload file to virustotal for analysis

    with open(file, "rb") as f:
        file_bin = f.read()
    print("UPLOADING")
    upload_package = {"file": (file.name, file_bin)}
    while True:
        response = requests.post(url, headers=HEADERS, files=upload_package)
        if handleError(response):
            break
    return response


def getAnalysis(response):

    #return file hash of the uploaded file after analysis is made available

    _id = response.json().get("data").get("id")
    url = f"https://www.virustotal.com/api/v3/analyses/{_id}"
    print(f"ID: {_id}")
    while True:
        print("WAITING FOR ANALYSIS REPORT")
        sleep(60)
        while True:
            response = requests.get(url, headers=HEADERS)
            if handleError(response):
                break
        if response.json().get("data").get("attributes").get("status") == "completed":
            f_hash = response.json().get("meta").get("file_info").get("sha256")
            return f_hash


def uploadURL():
    #get url to upload files to virustotal
    url = "https://www.virustotal.com/api/v3/files/upload_url"
    while True:
        response = requests.get(url, headers=HEADERS)
        if handleError(response):
            break
    return response.json()["data"]


def handleError(response):
    if response.status_code == 429:
        print("WAITING")
        sleep(60)
    if response.status_code == 401:
        raise Exception("Invalid API key")
    elif response.status_code not in (200, 404, 429):
        raise Exception(response.status_code)
    else:
        return True
    return False


def parseResponse(response):

#extract information from JSON

    json_obj = response.json().get("data").get("attributes")

    output = {}

    output["name"] = json_obj.get("meaningful_name")
    output["stats"] = json_obj.get("last_analysis_stats")
    output["engine_detected"] = {}

    for engine in json_obj.get("last_analysis_results").keys():
        if json_obj.get("last_analysis_results").get(engine).get("category") != "undetected":
            output.get("engine_detected")[engine] = {}
            output.get("engine_detected")[engine]["category"] = json_obj.get(
                "last_analysis_results").get(engine).get("category")
            output.get("engine_detected")[engine]["result"] = json_obj.get(
                "last_analysis_results").get(engine).get("result")

    output["votes"] = json_obj.get("total_votes")
    output["hash"] = {"sha1": json_obj.get(
        "sha1"), "sha254": json_obj.get("sha256")}
    output["size"] = json_obj.get("size")
    return output


def bar(parsed_response):
 
    total = 72
    undetected = parsed_response.get("stats").get("undetected")
    data = f"{'@'*undetected}{' '*(total-undetected)}"
    bar = bar = f"+{'-'*total}+\n|{data}| {undetected}/{total} did not detect\n+{'-'*total}+"
    return bar



parser = argparse.ArgumentParser(description="scan your files with virustotal")
parser.add_argument("file", action="store", nargs=1, help="file to scan")

parsed_arg = parser.parse_args()


for f in parsed_arg.file:

    file = Path(f)

    if not file.exists():
        raise Exception("File not found")

    # calculate file hash
    f_hash = hash_it(file, "sha256")

    # get file data against the file hash
    response = getData(f_hash)

#upload the file to virustotal if data not found
    if response.status_code == 404:

    

        if file.stat().st_size > 32000000:
            # for files larger than 32MB
            response = getData(getAnalysis(
                postFiles(file, uploadURL())))
        else:
      
            response = getData(getAnalysis(postFiles(file)))

    if response.status_code == 200:
     
        parsed_response =parseResponse(response)

        pprint(parsed_response, indent=2)
        print()
        print(bar(parsed_response))
    else:
        raise Exception(response.status_code)