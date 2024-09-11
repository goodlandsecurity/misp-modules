import json
from pymisp import MISPEvent, MISPObject
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
    'features': "The module takes a hash attribute as input and queries VirusTotal's API to fetch additional data about it. The result, if the hash has a threat label tag the MISPAttribute with it. Also, check if the hash is from a known software distributor and tag MISPAttribute with PyOTI taxonomy tag and create a file object describing the file.",
    'references': ['https://github.com/RH-ISAC/PyOTI', 'https://www.virustotal.com'],
    'input': 'A hash attribute (md5, sha1, sha256).',
    'output': 'Tagging of the queried hash attribute.',
}
moduleconfig = ["apikey"]


def run_enrichment(apikey: str, attribute: dict) -> dict:
    vt = VirusTotalV3(apikey)
    vt.file_hash = attribute['value']
    return vt.check_hash()


def parse_response(response: dict):
    attribute_mapping = {
        'md5': {'type': 'md5', 'object_relation': 'md5', 'distribution': 5},
        'sha1': {'type': 'sha1', 'object_relation': 'sha1', 'distribution': 5},
        'sha256': {'type': 'sha256', 'object_relation': 'sha256', 'distribution': 5},
        'imphash': {'type': 'imphash', 'object_relation': 'imphash', 'distribution': 5},
        'size': {'type': 'size-in-bytes', 'object_relation': 'size-in-bytes', 'distribution': 5},
        'meaningful_name': {'type': 'filename', 'object_relation': 'filename', 'distribution': 5}
    }
    misp_event = MISPEvent()
    misp_object = MISPObject('file')
    for feature, attribute in attribute_mapping.items():
        if feature in response.keys() and response[feature]:
            if feature in ('md5', 'sha1', 'sha256'):
                misp_attribute = {'value': response[feature], 'Tag': []}
                if response.get('popular_threat_classification'):
                    threat_label = response['popular_threat_classification']['suggested_threat_label']
                    misp_attribute['Tag'].append({'name': threat_label})
                if response.get('known_distributors'):
                    distributors = response['known_distributors']['distributors']
                    misp_attribute['Tag'].append({'name': 'pyoti:virustotal="known-distributor"'})
                    misp_attribute['comment'] = f'Distributors: {distributors}'
                misp_attribute.update(attribute)
                misp_object.add_attribute(**misp_attribute)
            else:
                misp_attribute = {'value': response[feature]}
                misp_attribute.update(attribute)
                misp_object.add_attribute(**misp_attribute)
    misp_event.add_object(**misp_object)
    event = json.loads(misp_event.to_json())
    results = {'Object': event['Object']}

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
        return parse_response(vt_response['data']['attributes'])

    elif vt_response.get('error'):
        misperrors['error'] = vt_response['error']['message']
        return misperrors


def introspection():
    return mispattributes


def version():
    moduleinfo['config'] = moduleconfig
    return moduleinfo

