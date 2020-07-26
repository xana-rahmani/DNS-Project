import requests
from Voting_System.settings import load_public_key

session = requests.Session()
BASE_URL = "http://127.0.0.1:8000/"

print(load_public_key('CA-public.key'))

def generateCertificaat():
    payload = {
        "national_code": "1055219379",
        "name": "xana"
    }
    response = session.post(url=BASE_URL + "generate-certificaat", data=payload)
    print(response)
    return response