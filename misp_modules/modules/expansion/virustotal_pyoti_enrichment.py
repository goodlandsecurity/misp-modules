import json
from pymisp import MISPEvent, MISPAttribute
from pyoti.multis import VirusTotalV3
from . import check_input_attribute, checking_error, standard_error_message


misperrors = {
    'error': 'Error'
}
mispattributes = {
    'input': [
        'md5',
        'sha1',
        'sha256'
    ],
    'format': 'misp_standard'
}
moduleinfo = {
    'version': '0.1',
    'author': 'goodlandsecurity',
    'description': 'Module to query VirusTotal API to get additional information about the input hash attribute.',
    'module-type': ['expansion'],
    'name': 'VT PyOTI Enrichment',
    'logo': 'virustotal.png',
    'requirements': ['Access to VirusTotal (apikey)'],
    'features': "The module takes a hash attribute as input and queries VirusTotal's API to fetch additional data about it. The result, if the hash has a threat label tag the MISPAttribute with it. Also, check if the hash is from a known software distributor and tag MISPAttribute with PyOTI taxonomy tag.",
    'references': ['https://github.com/RH-ISAC/PyOTI', 'https://www.virustotal.com'],
    'input': 'A hash attribute (md5, sha1, sha256).',
    'output': 'Tagging of the queried hash attribute.',
}
moduleconfig = ["apikey"]


def run_enrichment(apikey: str, attribute: dict) -> dict:
    vt = VirusTotalV3(apikey)
    vt.file_hash = attribute['value']
    return vt.check_hash()


def parse_response(response: dict, attribute: dict):
    misp_event = MISPEvent()
    misp_attribute = MISPAttribute()
    misp_attribute.from_dict(**attribute)

    if response['data']['attributes'].get('popular_threat_classification'):
        threat_label = response['data']['attributes']['popular_threat_classification']['suggested_threat_label']
        misp_attribute.add_tag(threat_label)

    if response['data']['attributes'].get('known_distributors'):
        misp_attribute.add_tag('pyoti:virustotal="known-distributor"')
        distributors = response['data']['attributes']['known_distributors']['distributors']
        misp_attribute.comment = f'Distributors: {distributors}'

    misp_event.add_attribute(**misp_attribute)
    event = json.loads(misp_event.to_json())
    results = {'Attribute': event['Attribute']}

    return {'results': results}


def handler(q=False):
    if q is False:
        return False
    request = json.loads(q)

    if not request.get('config') or not request['config'].get('apikey'):
        misperrors['error'] = 'A VirusTotal api key is required for this module!'
        return misperrors

    if not request.get('attribute') or not check_input_attribute(request['attribute'], requirements=('type', 'value')):
        misperrors['error'] = f'{standard_error_message}, {checking_error}.'
        return misperrors

    attribute = request['attribute']
    if attribute['type'] not in mispattributes['input']:
        misperrors['error'] = 'Unsupported attribute type!'
        return misperrors

    vt_response = run_enrichment(request['config']['apikey'], attribute)

    if vt_response.get('data'):
        return parse_response(vt_response, attribute)

    elif vt_response.get('error'):
        misperrors['error'] = vt_response['error']['message']
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

