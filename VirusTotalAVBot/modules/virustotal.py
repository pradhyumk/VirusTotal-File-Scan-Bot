import hashlib
import logging
import os
import requests
import time

from VirusTotalAVBot import VT_API

logger = logging.getLogger("VirusTotal Methods")
api_base_url = "https://www.virustotal.com/api/v3"
header = {'x-apikey': VT_API}


def vthash(filehash: str):
    """Returns the analysis data class for a file in VirusTotal's database"""

    endpoint_path = f'/files/{filehash}'
    endpoint = f"{api_base_url}{endpoint_path}"

    r = requests.get(endpoint, headers=header)

    if r.status_code == 404 and r.json()['error']['code'] == 'NotFoundError':
        return None
    elif r.status_code == 200:
        return analysisdata(r)


def replytofile(path: str, message):
    """Coordinates the process of searching if the file already exists on VirusTotal's database, or needs to be
    uploaded for analysis"""

    response = ''

    md5hash = findhash(path)

    endpoint_path = f'/files/{md5hash}'
    endpoint = f"{api_base_url}{endpoint_path}"

    r = requests.get(endpoint, headers=header)

    if r.status_code == 200:
        av_data = r.json()['data']['attributes']['last_analysis_results']
        response = simplifiedview(av_data, md5hash)

    elif r.status_code == 404:
        endpoint_path = '/files'
        file = open(path, 'rb')
        files = {'file': file}

        message.edit_text("File is uploading to VirusTotal.")

        if os.path.getsize(path) < 33554432:
            requests.post(f'{api_base_url}{endpoint_path}', files=files, headers=header)
        else:
            requests.post(uploadurl(), files=files, headers=header)

        file.close()
        del file

        message.edit_text("File has been uploaded to VirusTotal and is being analysed (90 seconds)")
        time.sleep(90)

        endpoint_path = f'/files/{md5hash}'
        endpoint = f"{api_base_url}{endpoint_path}"

        r = requests.get(endpoint, headers=header)

        if analysisdata(r) is None:
            return None
        else:
            av_data = analysisdata(r)

        response = simplifiedview(av_data, md5hash)

    return response


def simplifiedview(av_data: dict, filehash: str) -> str:
    """Builds and returns a simplified string containing basic information about the analysis"""

    neg_detections = 0
    pos_detections = 0
    error_detections = 0

    for engine in av_data:
        if av_data[engine]['category'] == 'malicious' or av_data[engine]['category'] == 'suspicious':
            neg_detections += 1
        elif av_data[engine]['category'] == 'undetected':
            pos_detections += 1
        elif av_data[engine]['category'] == 'timeout' or av_data[engine]['category'] == 'type-unsupported' \
                or av_data[engine]['category'] == 'failure':
            error_detections += 1

    vt_url = f'https://www.virustotal.com/gui/file/{filehash}'

    response = f"__VirusTotal Analysis Summary__:\n\nHash: `{filehash}`\n\nLink: [Click Here]({vt_url})\n\n❌" \
               f" **Negative: {neg_detections}**\n\n✅ Positive: {pos_detections}\n\n⚠ " \
               f"Error/Unsupported File: {error_detections}"

    return response


def detailedview(av_data: dict, filehash: str) -> str:
    """Builds and returns a string containing detailed information regarding the analysis for each antivirus engine"""
    vt_url = f'https://www.virustotal.com/gui/file/{filehash}'
    response = f"__VirusTotal Analysis Summary__:\n\nHash: `{filehash}`\n\nLink: [Click Here]({vt_url})\n\n"

    for engine in av_data:
        if av_data[engine]['category'] == 'malicious' or av_data[engine]['category'] == 'suspicious':
            response = response + f"❌ **{av_data[engine]['engine_name']}: {av_data[engine]['result']}**\n"

    for engine in av_data:
        if av_data[engine]['category'] == 'undetected':
            response = response + f"✅ {av_data[engine]['engine_name']}: Undetected\n"

    for engine in av_data:
        if av_data[engine]['category'] == 'timeout' or av_data[engine]['category'] == 'type-unsupported' \
                or av_data[engine]['category'] == 'failure':
            response = response + f"⚠ {av_data[engine]['engine_name']}: Unsupported File\n"

    return response


def uploadurl() -> str:
    """This method generates a special URL to upload files larger than 32MB. Do note that URLs generated from this
    endpoint will be one time use only."""

    r = requests.get(f"{api_base_url}/files/upload_url", headers=header)
    res = r.json()
    return res['data']


def findhash(path: str) -> str:
    """Calculates the MD5 Hash for the path specified"""

    h = hashlib.md5()

    filefrompath = open(path, 'rb')

    with filefrompath as file:
        chunk = file.read(1024)
        while len(chunk) > 0:
            h.update(chunk)
            chunk = file.read(1024)

    filehash = h.hexdigest()

    filefrompath.close()
    del filefrompath

    return filehash


def analysisdata(r):
    """Method to identify if analysis results are available in the json output"""
    if 'data' in r.json():
        if 'attributes' in r.json()['data']:
            if 'last_analysis_results' in r.json()['data']['attributes']:
                if r.json()['data']['attributes']['last_analysis_results']:
                    av_data = r.json()['data']['attributes']['last_analysis_results']
                    return av_data
                else:
                    return None
    else:
        return None
