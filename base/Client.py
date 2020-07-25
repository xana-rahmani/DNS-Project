import requests

session = requests.Session()
BASE_URL = "http://127.0.0.1:8000/"


def generateCertificaat():
    payload = {
        "national_code": "1055219379",
        "name": "xana"
    }
    response = session.post(url=BASE_URL + "generate-certificaat", data=payload)
    print(response.json())
    return response

# import base.Client as c
# c.generateCertificaat()