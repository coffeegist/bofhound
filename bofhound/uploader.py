import hmac
import hashlib
import base64
import requests
import datetime
import urllib3
from pathlib import Path
from typing import Optional

from bofhound.logger import logger


class BloodHoundUploader:

    def __init__(self, server, token_id, token_key):
        self.base_url = server
        self.token_id = token_id
        self.token_key = token_key
        self.upload_job_id = None
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def create_upload_job(self):
        try:
            r = self._request(
                method="POST",
                uri="/api/v2/file-upload/start"
            )

            if r.status_code != 201:
                logger.error(f"Failed to create upload job: HTTP {r.status_code} - {BloodHoundUploader.get_error(r)}")
                return None
            
            self.upload_job_id = r.json()["data"]["id"]
            logger.debug(f"BloodHound upload job created with ID: {self.upload_job_id}")
            return True
        
        except Exception as e:
            logger.error(f"Error creating upload job")
            logger.error(e)
            return False


    def upload_file(self, file):
        #
        # File comes in as PurePath object
        #  so create a Path object
        #
        file = Path(file)

        content_type = "application/json"
        if file.name.endswith(".zip"):
            content_type = "application/zip"
        
        try:
            r = self._request(
                method="POST",
                uri=f"/api/v2/file-upload/{self.upload_job_id}",
                body=file.read_bytes(),
                content_type=content_type
            )

            if r.status_code != 202:
                logger.error(f"Failed to upload file {file.name}: HTTP {r.status_code} - {BloodHoundUploader.get_error(r)}")

            logger.debug(f"Uploaded file {file.name} to BloodHound: HTTP {r.status_code}")

        except Exception as e:
            logger.error(f"Error uploading file {file.name}")
            logger.error(e)
            return None

    
    def close_upload_job(self):
        try:
            r = self._request(
                method="POST",
                uri=f"/api/v2/file-upload/{self.upload_job_id}/end"
            )

            if r.status_code != 200:
                logger.error(f"Failed to close upload job: HTTP {r.status_code} - {BloodHoundUploader.get_error(r)}")
                return None
            
            logger.debug(f"Ended BloodHound upload job successfully")

        except Exception as e:
            logger.error(f"Error closing upload job")
            logger.error(e)

    #
    # Sign requests
    #   https://bloodhound.specterops.io/integrations/bloodhound-api/working-with-api#use-your-api-key%2Fid-pair
    #
    def _request(self, method: str, uri: str, body: Optional[bytes] = None, content_type: str = "application/json") -> requests.Response:
        digester = hmac.new(self.token_key.encode(), None, hashlib.sha256)
        digester.update(f'{method}{uri}'.encode())
        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        datetime_formatted = datetime.datetime.now().astimezone().isoformat('T')
        digester.update(datetime_formatted[:13].encode())

        digester = hmac.new(digester.digest(), None, hashlib.sha256)

        if body is not None:
            digester.update(body)

        # Perform the request with the signed and expected headers
        return requests.request(
            method=method,
            url=f"{self.base_url}{uri}",
            headers={
                'User-Agent': 'bhe-python-sdk 0001',
                'Authorization': f'bhesignature {self.token_id}',
                'RequestDate': datetime_formatted,
                'Signature': base64.b64encode(digester.digest()),
                'Content-Type': content_type,
            },
            data=body,
            verify=False
        )

    @staticmethod
    def get_error(r):
        try:
            return r.json()["errors"][0]["message"]
        except Exception as e:
            logger.error(f"Error parsing response: {e}")
            return r.text
