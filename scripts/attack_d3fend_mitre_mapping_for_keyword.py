#################################################################################
#
#
#   author:         Robin dos Santos
#   name:           attack_d3fend_mitre_mapping_for_keyword.py 
#   description:    This script searches for mitre att&ck techniques which were
#                   used in attacks described as a keyword and gets detection
#                   and a response strategy from mitre d3fend
#   exports:        {keyword}_techniques.json
#                   heatmap_for_techniques_{keyword}.json
#
#
##################################################################################

import argparse
from attackcti import attack_client
import logging
import json
import yaml
import os
import glob
import requests
import re
from datetime import datetime
import markdown2
from bs4 import BeautifulSoup
from collections import defaultdict


logger = logging.getLogger('mapping d3fend with att&ck')
ch = logging.StreamHandler()
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
logger.addHandler(ch)
logger.setLevel(logging.INFO)

def_tech_descriptions = {}
full_mapping = False

def find_color_for_count(colors, count):
    keys = sorted(int(key) for key in colors if key.isdigit())
    
    selected_key = None
    for key in keys:
        if key <= count:
            selected_key = key
        else:
            break

    if selected_key is None or count > max(keys):
        selected_key = 'more'
    
    return colors[str(selected_key)]['color']

def create_json_for_visualization_in_mitre_navigator(all_techniques, keywords):
    techniques_count = {}
    
    result_data = {
        "description": f"Enterprise techniques which are used by {','.join(keywords)}",
        "name": f"Heat-Map for Techniques {','.join(keywords)}",
        "domain": "enterprise-attack",
        "versions": {
            "attack": "15",
            "navigator": "5.0.0",
            "layer": "4.5"
        },
        "gradient": {
            "colors": [],
            "minValue": 0,
            "maxValue": 1
        },
        "legendItems": [],
        "techniques": [],
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
        "selectVisibleTechniques": False,
        "sorting": 0,
        "layout": {
            "layout": "flat",
            "showName": True,
            "showID": False,
            "expandedSubtechniques": True
        },
    }
    
    colors = {
        "0": {"color": ""},
        "1": {"color": "#ff6666"},
        "2": {"color": "#f94444"},
        "4": {"color": "#e41b1b"},
        "6": {"color": "#f10000"},
        "11": {"color": "#950000"},
        "more": {"color": "#2b0000"}
    }

    for technique in all_techniques:
        
        if not technique["technique_id"]:
            logger.debug(f"Could not find technique_id for {technique['name']}")
            continue
        technique_id = technique["technique_id"]

        techniques_count[technique_id] = {"count": len(technique['detections']['att&ck']) + len(technique['detections']['d3fend']) + len(technique['detections']['sigma']) + len(technique['detections']['guardsight'])}
        
        count = techniques_count[technique_id]["count"]
        
        color = find_color_for_count(colors, count)

        links = []
        for response in technique['responses']['d3fend']:
            if len(links) == 0:
                links.append({
                    "divider": True
                })
                links.append({
                    "divider": True
                })
            if len(links) % 2 == 1:
                links.append({
                    "divider": True
                })
                
            links.append({
                "label": f"{response['title']}",
                "url": f"https://d3fend.mitre.org/technique/{response['id']}"
            })

        technique_entry = {
            "techniqueID": technique_id,
            "color": color,
            "comment": f"{techniques_count[technique_id]['count']} times",
            "showSubtechniques": True,
            "links": links
        }

        result_data["techniques"].append(technique_entry)
        result_data["gradient"]["colors"] = [v['color'] for _, v in colors.items()]

    result_data["legendItems"] = [{"label": str(k), "color": colors[str(k)]['color']} for k in colors.keys()]
    
    return result_data

def format_markdown_link(text):
    url_pattern = r'https?://[^\s]+'
    
    urls = re.findall(url_pattern, text)
    
    for url in urls:
        link_text = text.replace(url, '').strip()
        if link_text:
            if link_text.endswith(':'):
                link_text = link_text[:-1].strip()
            markdown_link = f"[{link_text}]({url})"
        else:
            markdown_link = f"[{url}]({url})"
        
        text = text.replace(url, markdown_link)
    return text
    

def markdown_to_html(markdown_text):
    if markdown_text:
        return markdown2.markdown(markdown_text)
    else:
        return None

def serialize_techniques(techniques):
    global markdown_to_html_bool
    serialized = []
    for t in techniques:
        serialized_t = json.loads(t.serialize())
        if 'description' in serialized_t:
            description = serialized_t['description']
        else:
            description = None
            
        references = []    
        description = markdown_to_html(description)
        for ref in serialized_t['external_references']:
            if 'url' in ref and 'description' in ref:
                references.append({
                        'url': markdown_to_html(f"[{ref['source_name']}]({ref['url']})"),
                        'description': ref['description']
                    })
            else:
                references.append(ref)
                
            
        serialized.append({
            "type": serialized_t['type'],
            "id": serialized_t['id'],
            "technique_id": serialized_t['external_references'][0]['external_id'],
            "parent_id": serialized_t['external_references'][0]['external_id'].split('.')[0] if '.' in serialized_t['external_references'][0]['external_id'] else None,
            "kill_chain_phases": serialized_t['kill_chain_phases'],
            "name": serialized_t['name'],
            "description": description,
            "external_references": references,
            "detections": {
                "att&ck": [],
                "d3fend": [],
                "sigma": [],
                "guardsight": []
            },
            "mitigations": [],
            "related_relationships": [],
            "responses": {
                "d3fend": [],
                "guardsight": []
            },
            "tests": {
                "atomic": []
            }
        })
    return serialized

def serialize_relationships(relationships):
    serialized = []
    for rel in relationships:
        serialized_rel = json.loads(rel.serialize())        
        if 'description' in serialized_rel:
            description = markdown_to_html(serialized_rel['description'])
        else:
            description = None
            
        serialized.append({
            "type": serialized_rel['type'],
            "id": serialized_rel['id'],
            "relationship_type": serialized_rel['relationship_type'],
            "target_ref": serialized_rel['target_ref'],
            "description": description,
            "source_ref": serialized_rel['source_ref']
        })
    return serialized

def serialize_groups(groups):
    serialized = []
    for group in groups:
        serialized_grp = json.loads(group.serialize())        
        if 'description' in serialized_grp:
            description = markdown_to_html(serialized_grp['description'])
        else:
            description = None
            
        serialized.append({
            "type": serialized_grp['type'],
            "id": serialized_grp['id'],
            "name": serialized_grp['name'],
            "aliases": serialized_grp['aliases'],
            "external_references": serialized_grp['external_references'],
            "description": description,
            "created_by_ref": serialized_grp['created_by_ref']
        })
    return serialized

def serialize_mitigations(mitigations):
    serialized = []
    for m in mitigations:
        serialized_m = json.loads(m.serialize())
        if 'description' in serialized_m:
            description = markdown_to_html(serialized_m['description'])
        else:
            description = None
        serialized.append({
            "type": serialized_m['type'],
            "id": serialized_m['id'],
            "mitigation_id": serialized_m['external_references'][0]["external_id"],
            "name": serialized_m['name'],
            "description": description,
            "created_by_ref": serialized_m['created_by_ref'],
            "object_marking_refs": serialized_m['object_marking_refs']
        })
    return serialized

def load_techniques(tech_path, no_cache):
    if os.path.exists(tech_path) and not no_cache:
        logger.info("Loading techniques from local JSON file.")
        with open(tech_path, 'r') as json_file:
            _all_techniques = json.load(json_file)
    else:
        logger.info("Retrieving all techniques from ATT&CK server")
        try:
            lift = attack_client()
        except Exception as e:
            logger.warning(f"Could not connect to cti-taxii.mitre.com : {str(e)}")
            logger.info("Using local cti repository")
            try:
                local_paths = {
                    "enterprise": "resources/cti/enterprise-attack",
                    "mobile": "resources/cti/mobile-attack",
                    "ics": "resources/cti/ics-attack"
                }
                lift = attack_client(local_paths=local_paths)
            except Exception as e:
                logger.error(f"Could not use local cti repository : {str(e)}")
                exit(1)
        _all_techniques = lift.get_techniques(enrich_data_sources=True)
        try:
            _all_techniques = lift.get_techniques(enrich_data_sources=True)
        except Exception as e:
            logger.error(f"Could not download techniques from ATT&CK server: {str(e)}")
            exit(2)
        logger.info("Finished retrieving all techniques")
        _all_techniques = serialize_techniques(_all_techniques)
        with open(tech_path, 'w+') as json_file:
            json.dump(_all_techniques, json_file)
        logger.info(f"Techniques saved to {tech_path}")
        
    return _all_techniques

def load_relationships(relations_path, no_cache):
    if os.path.exists(relations_path) and not no_cache:
        logger.info("Loading relationships from local JSON file.")
        with open(relations_path, 'r') as json_file:
            _all_relationships = json.load(json_file)
    else:
        logger.info("Retrieving all relationships from ATT&CK server")
        try:
            lift = attack_client()
        except Exception as e:
            logger.warning(f"Could not connect to cti-taxii.mitre.com : {str(e)}")
            logger.info("Using local cti repository")
            try:
                local_paths = {
                    "enterprise": "resources/cti/enterprise-attack",
                    "mobile": "resources/cti/mobile-attack",
                    "ics": "resources/cti/ics-attack"
                }
                lift = attack_client(local_paths=local_paths)
            except Exception as e:
                logger.error(f"Could not use local cti repository : {str(e)}")
                exit(1)
        try:
            _all_relationships = lift.get_relationships()
        except:
            logger.error("Could not download relationships from ATT&CK server")
            exit(2)
        _all_relationships = serialize_relationships(_all_relationships)
        with open(relations_path, 'w+') as json_file:
            json.dump(_all_relationships, json_file)
        logger.info(f"Relationships saved to {relations_path}")
    
    return _all_relationships

def load_groups(groups_path, no_cache):
    if os.path.exists(groups_path) and not no_cache:
        logger.info("Loading groups from local JSON file.")
        with open(groups_path, 'r') as json_file:
            _all_groups = json.load(json_file)
    else:
        logger.info("Retrieving all groups from ATT&CK server")
        try:
            lift = attack_client()
        except Exception as e:
            logger.warning(f"Could not connect to cti-taxii.mitre.com : {str(e)}")
            logger.info("Using local cti repository")
            try:
                local_paths = {
                    "enterprise": "resources/cti/enterprise-attack",
                    "mobile": "resources/cti/mobile-attack",
                    "ics": "resources/cti/ics-attack"
                }
                lift = attack_client(local_paths=local_paths)
            except Exception as e:
                logger.error(f"Could not use local cti repository : {str(e)}")
                exit(1)
        try:
            _all_groups = lift.get_groups()
        except:
            logger.error("Could not download groups from ATT&CK server")
            exit(2)
        _all_groups = serialize_groups(_all_groups)
        with open(groups_path, 'w+') as json_file:
            json.dump(_all_groups, json_file)
        logger.info(f"Relationships saved to {groups_path}")
    
    return _all_groups


def load_mitigations(mit_path, no_cache):
    if os.path.exists(mit_path) and not no_cache:
        logger.info("Loading mitigations from local JSON file.")
        with open(mit_path, 'r') as json_file:
            _all_mitigations = json.load(json_file)
    else:
        logger.info("Retrieving all mitigations from ATT&CK server")
        try:
            lift = attack_client()
        except Exception as e:
            logger.warning(f"Could not connect to cti-taxii.mitre.com : {str(e)}")
            logger.info("Using local cti repository")
            try:
                local_paths = {
                    "enterprise": "resources/cti/enterprise-attack",
                    "mobile": "resources/cti/mobile-attack",
                    "ics": "resources/cti/ics-attack"
                }
                lift = attack_client(local_paths=local_paths)
            except Exception as e:
                logger.error(f"Could not use local cti repository : {str(e)}")
                exit(1)
        _all_mitigations = lift.get_mitigations()
        logger.info("Finished retrieving all mitigations")
        _all_mitigations = serialize_mitigations(_all_mitigations)
        with open(mit_path, 'w+') as json_file:
            json.dump(_all_mitigations, json_file)
        logger.info(f"Mitigations saved to {mit_path}")
        
    return _all_mitigations

def load_sigma(no_cache, rules_folder_path="../sigma/rules", sigma_rules_path="../cache/all_sigma_detection_rules.json"):
    global full_mapping
    if os.path.exists(sigma_rules_path) and not no_cache and not full_mapping:
        logger.info("Loading sigma rules from local JSON file.")
        with open(sigma_rules_path, 'r', encoding='utf-8') as json_file:
            _all_sigma_rules_sanitized = json.load(json_file)
    else:
        logger.info("Retrieving all sigma rules from local folder")
        _all_sigma_rules = []
        for root, _, _ in os.walk(rules_folder_path):
            for file in glob.glob(os.path.join(root, '*.yml')):
                with open(file, 'r', encoding='utf-8') as stream:
                    try:
                        yaml_data = yaml.safe_load(stream)
                        yaml_data['file'] = file
                        _all_sigma_rules.append(yaml_data)
                    except yaml.YAMLError as exc:
                        print(f"Error parsing YAML file {file}: {exc}")
        logger.info(f"Sanitizing sigma structure")
        _all_sigma_rules_sanitized = sanitize_keys_in_place(_all_sigma_rules)
        logger.info(f"Done sanitizing sigma structure")
        with open(sigma_rules_path, 'w+', encoding='utf-8') as json_file:
            json.dump(_all_sigma_rules_sanitized, json_file)
        logger.info(f"All sigma rules saved to {sigma_rules_path}")
    
    return _all_sigma_rules_sanitized

def load_guardsight(no_cache, guardsight_responses_folder_path="../gsvsoc_cirt-playbook-battle-cards/Markdown", guardsight_responses_path="../cache/all_guardsight_responses.json"):
    if os.path.exists(guardsight_responses_path) and not no_cache:
        logger.info("Loading guardsight responses from local JSON file.")
        with open(guardsight_responses_path, 'r', encoding='utf-8') as json_file:
            _all_guardsight_responses = json.load(json_file)
    else:
        logger.info("Retrieving all guardsight responses from local folder")
        _all_guardsight_responses = []
        for root, _, _ in os.walk(guardsight_responses_folder_path):
            for file in glob.glob(os.path.join(root, '*.md')):
                with open(file, 'r', encoding='utf-8') as stream:
                    markdown_content = stream.read()
                    parsed_json = extract_data_from_markdown(markdown_content)
                    if parsed_json:
                        _all_guardsight_responses.append(parsed_json)
        with open(guardsight_responses_path, 'w+', encoding='utf-8') as json_file:
            json.dump(_all_guardsight_responses, json_file)
        logger.info(f"All guardsight rules saved to {guardsight_responses_path}")
    
    return _all_guardsight_responses

def load_atomic_red(no_cache, rules_folder_path="../atomic-red-team/atomics", atomic_rules_path="../cache/all_atomic_red_tests.json"):
    if os.path.exists(atomic_rules_path) and not no_cache:
        logger.info("Loading atomic red tests from local JSON file.")
        with open(atomic_rules_path, 'r', encoding='utf-8') as json_file:
            _all_atomic_tests = json.load(json_file)
    else:
        logger.info("Retrieving all atomic red tests from local folder")
        _all_atomic_tests = []
        for root, dirs, files in os.walk(rules_folder_path):
            dirs[:] = [d for d in dirs if d.startswith('T')]
            for file in glob.glob(os.path.join(root, '*.yaml')):
                with open(file, 'r', encoding='utf-8') as stream:
                    try:
                        yaml_data = yaml.safe_load(stream)
                        _all_atomic_tests.append((file, yaml_data))
                    except yaml.YAMLError as exc:
                        logger.error(f"Error parsing YAML file {file}: {exc}")
        with open(atomic_rules_path, 'w+', encoding='utf-8') as json_file:
            json.dump(_all_atomic_tests, json_file)
        logger.info(f"All atomic red tests saved to {atomic_rules_path}")
    
    return _all_atomic_tests

def loading(tech_path, relations_path, groups_path, mit_path, rules_folder_path, sigma_rules_path, guardsight_responses_folder_path, guardsight_responses_path, atomic_folder_path, atomic_test_path, no_cache):
    logger.info("Loading att&ck techniques")
    all_techniques = load_techniques(tech_path, no_cache)
    logger.info("Loading att&ck relationships")
    all_relationships = load_relationships(relations_path, no_cache)
    logger.info("Loading att&ck groups")
    all_groups = load_groups(groups_path, no_cache)
    logger.info("Loading att&ck mitigations")
    all_mitigations = load_mitigations(mit_path, no_cache)
    logger.info("Loading detection rules from sigma")
    all_sigma_detection_rules = load_sigma(no_cache, rules_folder_path, sigma_rules_path)
    logger.info(f"Loading playbook battle cards")
    all_guardsight_responses = load_guardsight(no_cache, guardsight_responses_folder_path, guardsight_responses_path)
    logger.info(f"Loading playbook battle cards")
    all_atomic_tests = load_atomic_red(no_cache, atomic_folder_path, atomic_test_path)
    
    return all_techniques, all_relationships, all_groups, all_mitigations, all_sigma_detection_rules, all_guardsight_responses, all_atomic_tests

def extract_data_from_markdown(md_content):
    html_content = markdown2.markdown(md_content)

    soup = BeautifulSoup(html_content, 'html.parser')

    json_data = {
        "title": "",
        "Preparation": [],
        "Identification": [],
        "Containment": [],
        "Recovery": [],
        "Lessons": [],
        "references": [],
        "technique_ids": [],
        "mitigation_ids": []
    }

    title_h5 = soup.find('h5')
    if title_h5 and title_h5.find('strong'):
        json_data['title'] = title_h5.find('strong').text.strip()

    sections = {
        "Preparation": "P",
        "Identification": "I",
        "Containment": "C",
        "Recovery": "R",
        "Lessons": "L",
        "References": "References"
    }

    for key, abbreviation in sections.items():
        header = soup.find(string=re.compile(f"\\({abbreviation}\\) {key}" if abbreviation != "References" else "References"))
        if header:
            content = header.find_next('ol')
            if content:
                items = content.find_all('li')
                for item in items:
                    text = item.get_text().strip()
                    if key == "References":
                        json_data['references'].append(text.strip())
                        if "/techniques/" in text:
                            technique_id = text.split('/techniques/')[1].split('/')[0]
                            if '/' in technique_id:
                                technique_id = technique_id.replace('/', '.')
                            json_data["technique_ids"].append(technique_id)
                            
                        if "/mitigations/" in text:
                            mitigation_id = text.split('/mitigations/')[1].split('/')[0]
                            json_data["mitigation_ids"].append(mitigation_id)
                    else:
                        json_data[key].append(text.strip())
                        

    for key in json_data:
        if isinstance(json_data[key], list):
            json_data[key] = sorted(set(json_data[key]))

    return json_data

def prepare_relationship_mapping(all_relationships):
    logger.info("Preparing mapping of relationship with att&ck by target_ref")
    relationship_map = {}
    for relationship in all_relationships:
        target_ref = relationship.get("target_ref")
        if target_ref not in relationship_map:
            relationship_map[target_ref] = []

        relationship_map[target_ref].append(relationship)
    
    return relationship_map

def map_relationships_to_techniques(all_techniques, all_relationships):
    logger.info("Prepare relationship mapping")
    relationship_map = prepare_relationship_mapping(all_relationships)
    
    for technique in all_techniques:
        technique_id = technique.get("id")
        if technique_id in relationship_map:
            maps_for_technique = relationship_map[technique_id]
            for map_for_technique in maps_for_technique:
                if map_for_technique['relationship_type'] == 'detects':
                    description = map_for_technique.get('description', '')
                    
                    technique['detections']['att&ck'].append({
                            "title": map_for_technique.get('id'),
                            "id": map_for_technique.get('id'),
                            "description": description,
                            "references": map_for_technique.get('source_ref'),
                            "authors": None
                        })
                elif map_for_technique['relationship_type'] == 'mitigates':
                    technique['mitigations'].append(map_for_technique)
                else:
                    technique['related_relationships'].append(map_for_technique)
    return all_techniques

def map_groups_to_techniques(all_techniques, all_groups, all_relationships):
    group_map = {group['id']: group['name'] for group in all_groups}
    
    relationship_map = prepare_relationship_mapping(all_relationships)
    
    for technique in all_techniques:
        technique_id = technique.get('id')
        groups = []

        if technique_id in relationship_map:
            for relationship in relationship_map[technique_id]:
                if relationship['relationship_type'] == 'uses' and relationship['source_ref'].startswith('intrusion-set'):
                    group_id = relationship['source_ref']
                    if group_id in group_map:
                        groups.append(group_map[group_id])

        technique['groups'] = groups

    return all_techniques


def map_mitigations_to_techniques(all_techniques, all_mitigations):
    mitigation_dict = {mitigation['id']: mitigation for mitigation in all_mitigations}

    for technique in all_techniques:
        for tech_mitigation in technique['mitigations']:
            if tech_mitigation['source_ref'] in mitigation_dict:
                tech_mitigation['mitigation_id'] = mitigation_dict[tech_mitigation['source_ref']]['mitigation_id']
            else:
                print(f"{tech_mitigation['source_ref']} not in mitigation_dict")
    
    return all_techniques

def map_guardsight_to_techniques(filtered_techniques, all_guardsight_responses):
    techniques_by_id = {technique['technique_id']: technique for technique in filtered_techniques}

    mitigations_to_techniques = {}
    for technique in filtered_techniques:
        for mitigation in technique['mitigations']:
            if 'mitigation_id' in mitigation:
                if mitigation['mitigation_id'] not in mitigations_to_techniques:
                    mitigations_to_techniques[mitigation['mitigation_id']] = []
                mitigations_to_techniques[mitigation['mitigation_id']].append(technique)

    for response in all_guardsight_responses:
        response_technique_ids = set(response['technique_ids'])
        response_mitigation_ids = set(response['mitigation_ids'])

        for technique_id in response_technique_ids:
            if technique_id in techniques_by_id:

                references = []
                for ref in response.get('references', []):
                    references.append(markdown_to_html(format_markdown_link(ref)))
                    
                identification = []
                for ide in response.get('Identification', []):
                    identification.append(markdown_to_html(ide))
                    
                preparation = []
                for prep in response.get('Preparation', []):
                    preparation.append(markdown_to_html(prep))        
                    
                containment = []
                for cont in response.get('Containment', []):
                    containment.append(markdown_to_html(cont))    
                
                recovery = []
                for rec in response.get('Recovery', []):
                    recovery.append(markdown_to_html(rec))    
                    
                lessons = []
                for les in response.get('Lessons', []):
                    lessons.append(markdown_to_html(les))    
                    
                techniques_by_id[technique_id]['detections']['guardsight'].append({
                            "title": response.get('title'),
                            "id": response.get('title'),
                            "detection": identification,
                            "references": references,
                            "authors": None
                        })
                techniques_by_id[technique_id]['responses']['guardsight'].append({
                            "title": response.get('title'),
                            "id": response.get('title'),
                            "description": response.get('title'),
                            "references": references,
                            "response": {
                                "preparation": preparation,
                                "containment": containment,
                                "recovery": recovery,
                                "lessons": lessons
                            },
                            "authors": None
                        })

        for mitigation_id in response_mitigation_ids:
            if mitigation_id in mitigations_to_techniques:
                for technique in mitigations_to_techniques[mitigation_id]:
                    references = []
                    for ref in response.get('references', []):
                        references.append(markdown_to_html(format_markdown_link(ref)))
                        
                    identification = []
                    for ide in response.get('Identification', []):
                        identification.append(markdown_to_html(ide))    
                        
                    preparation = []
                    for prep in response.get('Preparation', []):
                        preparation.append(markdown_to_html(prep))        
                        
                    containment = []
                    for cont in response.get('Containment', []):
                        containment.append(markdown_to_html(cont))    
                    
                    recovery = []
                    for rec in response.get('Recovery', []):
                        recovery.append(markdown_to_html(rec))    
                        
                    lessons = []
                    for les in response.get('Lessons', []):
                        lessons.append(markdown_to_html(les))  
                    
                    
                    technique['detections']['guardsight'].append({
                        "title": response.get('title'),
                        "id": response.get('title'),
                        "detection": identification,
                        "references": references,
                        "authors": None
                    })
                    technique['responses']['guardsight'].append({
                            "title": response.get('title'),
                            "id": response.get('title'),
                            "description": response.get('title'),
                            "references": references,
                            "response": {
                                "preparation": preparation,
                                "containment": containment,
                                "recovery": recovery,
                                "lessons": lessons
                            },
                            "authors": None
                        })
    return filtered_techniques
 
def replace_keys(obj):
    if isinstance(obj, dict):
        new_obj = {}
        for k, v in obj.items():
            new_key = k.replace('|', '_').replace('.', '_')
            new_obj[new_key] = replace_keys(v)
        return new_obj
    elif isinstance(obj, list):
        return [replace_keys(item) for item in obj]
    else:
        return obj

def sanitize_keys_in_place(all_sigma_rules):
    sanitized_rules = []
    for yaml_data in all_sigma_rules:
        sanitized_data = replace_keys(yaml_data)
        sanitized_rules.append(sanitized_data)
    return sanitized_rules

 
def map_atomic_tests_to_techniques(filtered_techniques, all_atomic_tests):
    techniques_by_id = {technique['technique_id']: technique for technique in filtered_techniques}

    for atomic in all_atomic_tests:
        _, test_info = atomic[0], atomic[1]
        if test_info['attack_technique'] in techniques_by_id:
            for test in test_info['atomic_tests']:
                
                description = test.get('description')
                
                techniques_by_id[test_info['attack_technique']]['tests']['atomic'].append({
                            "title": test.get('name'),
                            "id": test.get('auto_generated_guid'),
                            "description": description,
                            "platforms": test.get('supported_platforms'),
                            "input_arguments": test.get('input_arguments'),
                            "dependency_executor_name": test.get('dependency_executor_name'),
                            "dependencies": test.get('dependencies'),
                            "executor": test.get('executor')
                        })

    return filtered_techniques 
 
def remove_duplicates(items):
    seen = set()
    unique_items = []
    for item in items:
        item_str = json.dumps(item, sort_keys=True)
        if item_str not in seen:
            seen.add(item_str)
            unique_items.append(item)
    return unique_items
 
def remove_technique_duplicates(all_techniques):
    for technique in all_techniques:
        for key in ['att&ck', 'd3fend', 'sigma', 'guardsight']:
            if key in technique['detections']:
                technique['detections'][key] = remove_duplicates(technique['detections'][key])

        for key in ['d3fend', 'guardsight']:
            if key in technique['responses']:
                technique['responses'][key] = remove_duplicates(technique['responses'][key])
    
    return all_techniques        
        
def preprocess_references(mapped_techniques):
    for technique in mapped_techniques:
        technique['references'] = []
                
        for relationship in technique['related_relationships']:
            if 'description' in relationship and relationship.get('description'):
                technique['references'].append({
                    "type": "uses",
                    "description": relationship.get('description', ''),
                    "url": relationship.get('url', ''),
                    "id": relationship.get('id', '')
                })

        del technique['related_relationships']

        for reference in technique['external_references']:
            if 'description' in reference:
                technique['references'].append({
                    "type": "ref",
                    "description": reference['description'],
                    "id": relationship.get('id', '')
                })
                
    return mapped_techniques


def filter_for_keywords(mapped_techniques, keywords, interrelation_keywords):
    filtered_techniques = []
    for technique in mapped_techniques:
        references = []
        
        descriptions_and_references = []
        
        for ref in technique['references']:
            if ref['description'] is None:
                logger.info(f"this technique has description none - name: {technique['name']} - ref: {ref}")
            else:
                descriptions_and_references.append({
                    "description": ref['description'].lower(),
                    "reference": {
                        "type": ref['type'],
                        "description": ref['description']
                    }
                })

        unique_references = set()

        keyword_in_description = {keyword.lower(): False for keyword in keywords}
        for item in descriptions_and_references:
            description = item['description']
            reference = item['reference']
            for keyword in keyword_in_description.keys():
                if keyword.lower() in description:
                    keyword_in_description[keyword] = True
                    unique_references.add((reference['type'], reference['description']))

        if (interrelation_keywords == "AND" or interrelation_keywords == "SINGLE") and all(keyword_in_description.values()):
            for ref_type, desc in unique_references:
                references.append({"type": ref_type, "description": desc})
            technique['references'] = references
            filtered_techniques.append(technique)
        elif interrelation_keywords == "OR" and any(keyword_in_description.values()):
            for ref_type, desc in unique_references:
                references.append({"type": ref_type, "description": desc})
            technique['references'] = references
            filtered_techniques.append(technique)


    return filtered_techniques

def filter_for_groups(mapped_techniques, groups, interrelation_groups):
    filtered_techniques = []

    for technique in mapped_techniques:
        current_technique_groups = technique.get('groups', [])
        
        if interrelation_groups == 'OR':
            any_group_present = False
            for group in groups:
                if group in current_technique_groups:
                    any_group_present = True
                    break
            
            if any_group_present:
                filtered_techniques.append(technique)
        else :
            all_groups_present = True
            for group in groups:
                if group not in current_technique_groups:
                    all_groups_present = False
                    break
            
            if all_groups_present:
                filtered_techniques.append(technique)


    return filtered_techniques


def merging_filtered_techniques_keywords_groups(filtered_techniques_keywords, filtered_techniques_groups, interrelation_keywords_and_groups):
    dict1 = {obj['id']: obj for obj in filtered_techniques_keywords}
    dict2 = {obj['id']: obj for obj in filtered_techniques_groups}
    
    if interrelation_keywords_and_groups == 'OR':
        combined_dict = {**dict1, **dict2}
        return list(combined_dict.values())
    else:
        common_keys = dict1.keys() & dict2.keys()
        return [dict1[key] for key in common_keys]

def map_sigma_detection_rules_to_attack_techniques(all_sigma_detection_rules, filtered_mapped_techniques):
    for technique in filtered_mapped_techniques:
        for sigma_detection_rule in all_sigma_detection_rules:
                
            if "tags" not in sigma_detection_rule:
                logger.debug("Could not find tag in sigma detection rule")
                continue
                
            for tag in sigma_detection_rule['tags']:
                if 'attack.' not in tag:
                    logger.debug("Not a attack tag")
                    continue
                if tag.replace("attack.", "") == technique['technique_id'].lower():
                    references = sigma_detection_rule.get('references', [])
                    description = markdown_to_html(sigma_detection_rule['description'])
                        
                    references = []
                    for ref in sigma_detection_rule.get('references', []):
                        references.append(markdown_to_html(format_markdown_link(ref)))
                    
                    technique['detections']['sigma'].append({
                            "file": sigma_detection_rule.get('file'),
                            "title": sigma_detection_rule.get('title'),
                            "id": sigma_detection_rule.get('id'),
                            "description": description,
                            "references": references,
                            "authors": sigma_detection_rule.get('author'),
                            "date": sigma_detection_rule.get('date'),
                            "level": sigma_detection_rule.get('level'),
                            "tags": sigma_detection_rule['tags'],
                            "logsource": sigma_detection_rule.get('logsource'),
                            "detection": sigma_detection_rule.get('detection')
                        })
    return filtered_mapped_techniques

def get_description_for_d3fend_technique(def_tech_id):
    url = f"https://d3fend.mitre.org/api/technique/d3f:{def_tech_id}.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.debug(f"No d3fend technique description")
        return None

def get_d3fend_for_attack_techniques(all_techniques):
    for technique in all_techniques:
        url = f"https://d3fend.mitre.org/api/offensive-technique/attack/{technique['technique_id']}.json"
        try:
            response = requests.get(url)
            response.raise_for_status()
            _d3fend_response = response.json()
            if len(_d3fend_response['off_to_def']['results']['bindings']) > 0:
                for binding in _d3fend_response['off_to_def']['results']['bindings']:
                    if 'def_tech_label' in binding:
                        def_tech_id = binding['def_tech']['value'].split('#')[-1]
                        if def_tech_id not in def_tech_descriptions:
                            def_tech_descriptions[def_tech_id] = get_description_for_d3fend_technique(def_tech_id)
                        def_tech_description = None
                        def_tech_references = []
                        def_tech_authors = []
                        if def_tech_descriptions[def_tech_id] is not None:
                            if 'description' in def_tech_descriptions[def_tech_id]:
                                if len(def_tech_descriptions[def_tech_id]['description']['@graph']) > 0:
                                    def_tech_description = def_tech_descriptions[def_tech_id]['description']['@graph'][0]
                            if 'references' in def_tech_descriptions[def_tech_id]:
                                if len(def_tech_descriptions[def_tech_id]['description']['@graph']) > 0:
                                    if 'd3f:has-link' in def_tech_descriptions[def_tech_id]['description']['@graph'][0]:
                                        def_tech_references.append(def_tech_descriptions[def_tech_id]['references']['@graph'][0]['d3f:has-link']['@value'])
                                        def_tech_authors = def_tech_descriptions[def_tech_id]['references']['@graph'][0].get('d3f:kb-author').split(',')
                            
                            response = def_tech_description.get('d3f:kb-article')
                            technique['responses']["d3fend"].append({
                                "title": f"{binding['def_tactic_label']['value']} - {binding['def_tech_label']['value']}" ,
                                "id": f"{def_tech_description['@id']}",
                                "description": markdown_to_html(f"{def_tech_description['d3f:definition']}"),
                                "response": markdown_to_html(response),
                                "references": def_tech_references,
                                "authors": def_tech_authors
                            })
        except requests.RequestException as e:
            logger.debug(f"No d3fend attack found on d3fend server for {technique['name']}")
        
    return all_techniques
   
   
def filter_attack_techniques_detection(all_techniques):
    for technique in all_techniques:
        responses_without_detect = []
        for response in technique['responses']["d3fend"]:
            if response['title'].startswith('Detect'):
                technique['detections']['d3fend'].append({
                    "title": response['title'],
                    "id": response['id'],
                    "description": response['description'],
                    "detection": response['response'],
                    "references": response['references'],
                    "authors": response['authors']
                })
            else:
                responses_without_detect.append(response)
        technique['responses']["d3fend"] = responses_without_detect
        
    return all_techniques

def filter_out_techniques_without_response(all_techniques):
    return [technique for technique in all_techniques if len(technique['responses']["d3fend"]) > 0 or len(technique['responses']['guardsight']) > 0 ]

def analyze_and_update_techniques(filtered_techniques, overall_stats):

    total_techniques = len(filtered_techniques)
    unique_responses = set()
    unique_detections = set()
    unique_tests = set()

    for technique in filtered_techniques:
        tech_detections = defaultdict(int)
        tech_responses = defaultdict(int)
        tech_tests= defaultdict(int)

        for source in ['att&ck', 'd3fend', 'sigma', 'guardsight']:
            detections = technique['detections'].get(source, [])
            tech_detections[source] += len(detections)
            unique_detections.update(d['id'] for d in detections)

        for source in ['d3fend', 'guardsight']:
            responses = technique['responses'].get(source, [])
            tech_responses[source] += len(responses)
            unique_responses.update(r['id'] for r in responses)
            
        for source in ['atomic']:
            tests = technique['tests'].get(source, [])
            tech_tests[source] += len(tests)
            unique_tests.update(r['id'] for r in tests)

        technique['stats'] = {
            'detections': dict(tech_detections),
            'responses': dict(tech_responses),
            'total_detections': sum(tech_detections.values()),
            'total_responses': sum(tech_responses.values()),
            'total_tests': sum(tech_tests.values())
        }

        overall_stats['total_used_techniques'] = total_techniques
        overall_stats['unique_responses'] = len(unique_responses)
        overall_stats['unique_detections'] = len(unique_detections)
        overall_stats['unique_tests'] = len(unique_tests)

    return overall_stats, filtered_techniques

    
def filter_and_export(filtered_techniques, interrelation_keywords_and_groups, keywords, interrelation_keywords, groups, interrelation_groups, stats, timestamp, no_cache, techniques_with_mapped_responses_with_guardsight, full_mapping_path, heat_map_with_mapped_guardsight_path):
    global full_mapping
    if not full_mapping:
        if len(keywords) > 0:
            logger.info("Filtering mapped att&ck techniques for keywords")
            filtered_techniques_keywords = filter_for_keywords(filtered_techniques, keywords, interrelation_keywords)
            logger.info("Done filtering mapped att&ck techniques for keywords")
        
        if len(groups) > 0:
            logger.info("Filtering mapped att&ck techniques for groups")
            filtered_techniques_groups = filter_for_groups(filtered_techniques, groups, interrelation_groups)
            logger.info("Done filtering mapped att&ck techniques for groups")
    
        if len(groups) > 0 and len(keywords) > 0:
            logger.info("Merging filtered techniques keywords and filtered techniques groups")
            filtered_techniques = merging_filtered_techniques_keywords_groups(filtered_techniques_keywords, filtered_techniques_groups, interrelation_keywords_and_groups)
            logger.info("Done merging filtered techniques keywords and filtered techniques groups")
        else:
            if len(keywords) > 0:
                filtered_techniques = filtered_techniques_keywords
            else:
                filtered_techniques = filtered_techniques_groups

    
    
    if len(filtered_techniques) > 0:
        logger.info(f"Analyzing results")
        stats, filtered_techniques = analyze_and_update_techniques(filtered_techniques, stats)
        logger.info("Done analyzing results")
    else:
        logger.info(f"Skipping analyzing, because no techniques where found.")
        exit(3)
        
    logger.info(f"Exporting att&ck techniques with detections and additional guardsight responses for keyword {','.join(keywords)}")
    export_object = {
        "interrelation_keywords_and_groups": interrelation_keywords_and_groups,
        "keywords": keywords,
        "interrelation_keywords": interrelation_keywords,
        "groups": groups,
        "interrelation_groups": interrelation_groups,
        "techniques": filtered_techniques,
        "stats": stats,
        "created": timestamp,
        "use_cache": not no_cache,
        "filename": techniques_with_mapped_responses_with_guardsight.split('/')[-1],
        "id": techniques_with_mapped_responses_with_guardsight.split(".json")[0]
    }
    
    if len(keywords) == 0 and len(groups) == 0:
        with open(full_mapping_path, 'w+') as json_file:
            json.dump(export_object, json_file)
        logger.info(f"New cache of full mapping")
    else:
        with open(techniques_with_mapped_responses_with_guardsight, 'w+') as json_file:
            json.dump(export_object, json_file)
        logger.info(f"Done exporting")


def main(args):
    global full_mapping
    full_mapping = args.fullmapping
    full_mapping_path = "cache/full_mapping.json"
    no_cache = True
    keywords = args.keywords
    groups = args.groups    


    if not keywords or full_mapping:
        keywords = []
    
    logger.info(f"Keywords: {args.keywords}")
    
    if not groups or full_mapping:
        groups = []
        
    logger.info(f"Groups: {args.groups}")
    
    
    interrelation_keywords_and_groups = args.interrelationkeywordsandgroups
        
    interrelation_keywords = args.interrelationkeywords    
        
    interrelation_groups = args.interrelationgroups
    
        
    if not full_mapping:
        no_cache = args.nocache
    timestamp = datetime.now().timestamp()
            
        
    if args.outputpath:
        techniques_with_mapped_responses_with_guardsight = args.outputpath
    else:
        cache_string = ''
        if not no_cache:
            cache_string = "_cached"
        techniques_with_mapped_responses_with_guardsight = f"../data/techniques_{f'{interrelation_keywords_and_groups}-{interrelation_keywords}-'.join(keywords)}_{f'-{interrelation_groups}-'.join(groups)}_{cache_string}_{timestamp}.json"
    
    logger.info(f"Input parameters: {args}")
    
    # Cache paths
    tech_path = "cache/all_techniques.json"
    relations_path = "cache/all_relationships.json"
    groups_path = "cache/all_groups.json"
    sigma_rules_path = "cache/all_sigma_detection_rules.json"
    mit_path = "cache/all_mitigations.json"
    atomic_test_path = "cache/all_atomic_tests.json"
    
    guardsight_responses_folder_path="resources/gsvsoc_cirt-playbook-battle-cards/Markdown"
    atomic_folder_path = "resources/atomic-red-team/atomics"
    
    rules_folder_path = "resources/sigma/rules"
    guardsight_responses_path="cache/all_guardsight_responses.json"
    
    # Output paths
    export_path = f"output/{f'{interrelation_keywords_and_groups}-{interrelation_keywords}-'.join(keywords)}_{f'-{interrelation_groups}-'.join(groups)}_in_techniques.json"
    heat_map_path = f"output/heatmap_SIOR_for_techniques_{f'{interrelation_keywords_and_groups}-{interrelation_keywords}-'.join(keywords)}_{f'-{interrelation_groups}-'.join(groups)}.json"
    

    heat_map_with_mapped_guardsight_path = f"output/heatmap_SIOR_for_techniques_{f'{interrelation_keywords_and_groups}-{interrelation_keywords}-'.join(keywords)}_{f'-{interrelation_groups}-'.join(groups)}.json"

    if os.path.exists(full_mapping_path) and not full_mapping:
        with open(full_mapping_path, 'r') as json_file:
            _full_mapping = json.load(json_file)
        filter_and_export(_full_mapping['techniques'], interrelation_keywords_and_groups, keywords, interrelation_keywords, groups, interrelation_groups, _full_mapping['stats'], timestamp, no_cache, techniques_with_mapped_responses_with_guardsight, full_mapping_path, heat_map_with_mapped_guardsight_path)
        
        logger.info(f"Exiting script")
        exit(0)

    
    os.makedirs('cache', exist_ok=True)
    os.makedirs('output', exist_ok=True)
    os.makedirs('../data', exist_ok=True)
    
    

    logger.info("Starting loading")
    all_techniques, all_relationships, all_groups, all_mitigations, all_sigma_detection_rules, all_guardsight_responses, all_atomic_tests = loading(tech_path, relations_path, groups_path, mit_path, rules_folder_path, sigma_rules_path, guardsight_responses_folder_path, guardsight_responses_path, atomic_folder_path, atomic_test_path, no_cache)
    logger.info("Done loading")
    all_techniques_length = len(all_techniques)
    
    logger.info("Mapping att&ck relationships to att&ck techniques")
    all_techniques = map_relationships_to_techniques(all_techniques, all_relationships)
    logger.info("Done mapping att&ck relationships to att&ck techniques")
    
    logger.info("Mapping att&ck groups to att&ck techniques")
    all_techniques = map_groups_to_techniques(all_techniques, all_groups, all_relationships)
    logger.info("Done mapping att&ck groups to att&ck techniques")
    
    logger.info(f"Mapping mitigations to techniques")
    all_techniques = map_mitigations_to_techniques(all_techniques, all_mitigations)
    logger.info(f"Done mapping mitigations to techniques")

    if full_mapping:
        logger.info("Process references")
        all_techniques = preprocess_references(all_techniques)
        logger.info("Done processing references")

    logger.info("Getting d3fend responses for att&ck techniques")
    all_techniques = get_d3fend_for_attack_techniques(all_techniques)
    logger.info("Done getting d3fend responses for att&ck techniques")
    
    logger.info("Mapping detection rules from sigma to att&ck techniques")
    all_techniques = map_sigma_detection_rules_to_attack_techniques(all_sigma_detection_rules, all_techniques)
    logger.info("Done mapping detection rules from sigma to att&ck techniques")
    
    logger.info(f"Mapping guardsight responses to techniques")
    all_techniques = map_guardsight_to_techniques(all_techniques, all_guardsight_responses)
    logger.info(f"Done mapping guardsight responses to techniques")

    logger.info(f"Mapping atomic red tests to techniques")
    all_techniques = map_atomic_tests_to_techniques(all_techniques, all_atomic_tests)
    logger.info(f"Done mapping atomic red tests to techniques")

    logger.info("Filtering d3fend detections to add to att&ck detections")
    all_techniques = filter_attack_techniques_detection(all_techniques)
    logger.info("Done filtering d3fend detections to add to att&ck detections")

    logger.info(f"Exporting att&ck techniques with detections and responses for keywords {','.join(keywords)} and groups {','.join(groups)}")
    export_object = {
        "interrelation_keywords_and_groups": interrelation_keywords_and_groups,
        "keywords": keywords,
        "interrelation_keywords": interrelation_keywords,
        "groups": groups,
        "interrelation_groups": interrelation_groups,
        "techniques": all_techniques,
        "created": timestamp
    }
    with open(export_path, 'w+') as json_file:
        json.dump(export_object, json_file)
    logger.info(f"Done exporting")

    logger.info(f"Remove duplicates")
    filtered_techniques = remove_technique_duplicates(all_techniques)
    logger.info(f"Done removing duplicates")

    #logger.info(f"Filtering out techniques without responses")
    #filtered_techniques = filter_out_techniques_without_response(filtered_techniques)
    #logger.info(f"Done filtering out techniques without responses")

    stats = {
        'all_techniques': all_techniques_length,
        'all_relationships': len(all_relationships),
        'all_groups': len(all_groups),
        'all_mitigations': len(all_mitigations),
        'all_guardsight': len(all_guardsight_responses),
        'all_sigma': len(all_sigma_detection_rules),
        'all_tests': sum(len(entry[1]['atomic_tests']) for entry in all_atomic_tests)
    }
    
    filter_and_export(filtered_techniques, interrelation_keywords_and_groups, keywords, interrelation_keywords, groups, interrelation_groups, stats, timestamp, no_cache, techniques_with_mapped_responses_with_guardsight, full_mapping_path, heat_map_with_mapped_guardsight_path)
    
    logger.info(f"Exiting script")
    exit(0)

if __name__ == "__main__":
    abspath = os.path.abspath(__file__)
    dname = os.path.dirname(abspath)
    os.chdir(dname)
    parser = argparse.ArgumentParser("simple_example")
    parser.add_argument('-f', '--fullmapping', action=argparse.BooleanOptionalAction, required=False, default=False)
    parser.add_argument('-ikg','--interrelationkeywordsandgroups', help='Interrelation keywords and groups (AND or OR)', required=False, choices=['AND', 'OR', 'SINGLE'], default="OR", type=str)
    parser.add_argument('-k','--keywords', nargs='+', help='Keyword(s)', required=False)
    parser.add_argument('-ik','--interrelationkeywords', help='Interrelation keywords (AND or OR)', required=False, choices=['AND', 'OR', 'SINGLE'], default="OR", type=str)
    parser.add_argument('-g','--groups', nargs='+', help='Group(s)', required=False)
    parser.add_argument('-ig','--interrelationgroups', help='Interrelation keywords (AND or OR)', required=False, choices=['AND', 'OR', 'SINGLE'], default="OR", type=str)
    parser.add_argument('-n', '--nocache', action=argparse.BooleanOptionalAction, required=False, default=False)
    parser.add_argument('-o', '--outputpath', help='Export path for json', required=False, type=str)
    args = parser.parse_args()
    main(args)