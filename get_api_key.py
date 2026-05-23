import requests
import xml.etree.ElementTree as ET

query = {'type':'keygen', 'user':'ADMIN', 'password':'PASSWORD'}

response = requests.get('https://IP-PANORAMA/api', params=query, verify=False)

# Parse the XML string
root = ET.fromstring(response.text)

# Find the key element and get its text
api_key = root.find(".//key").text

print(api_key)
