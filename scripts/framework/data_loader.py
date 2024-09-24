import json
import logging
import yaml
import glob
import os
from attackcti import attack_client
from typing import Dict, Any, List
from config import TECH_PATH, RELATIONS_PATH, GROUPS_PATH, MIT_PATH, SIGMA_RULES_PATH, SIGMA_RULES_FOLDER, GUARDSIGHT_RESPONSES_PATH, GUARDSIGHT_RESPONSES_FOLDER, ATOMIC_TEST_PATH, ATOMIC_FOLDER
from utils import markdown_to_html, extract_data_from_markdown, format_markdown_link

logger = logging.getLogger(__name__)

def load_json(file_path: str) -> Dict[str, Any]:
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        logger.error(f"File not found: {file_path}")
        return {}

def load_techniques(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(TECH_PATH) and not no_cache:
        logger.info("Loading techniques from local JSON file.")
        return load_json(TECH_PATH)
    else:
        logger.info("Retrieving all techniques from ATT&CK server")
        try:
            lift = attack_client()
            all_techniques = lift.get_techniques(enrich_data_sources=True)
            all_techniques = serialize_techniques(all_techniques)
            with open(TECH_PATH, 'w+') as json_file:
                json.dump(all_techniques, json_file)
            logger.info(f"Techniques saved to {TECH_PATH}")
            return all_techniques
        except Exception as e:
            logger.error(f"Could not download techniques from ATT&CK server: {str(e)}")
            exit(2)

def load_relationships(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(RELATIONS_PATH) and not no_cache:
        logger.info("Loading relationships from local JSON file.")
        return load_json(RELATIONS_PATH)
    else:
        logger.info("Retrieving all relationships from ATT&CK server")
        try:
            lift = attack_client()
            all_relationships = lift.get_relationships()
            all_relationships = serialize_relationships(all_relationships)
            with open(RELATIONS_PATH, 'w+') as json_file:
                json.dump(all_relationships, json_file)
            logger.info(f"Relationships saved to {RELATIONS_PATH}")
            return all_relationships
        except Exception as e:
            logger.error(f"Could not download relationships from ATT&CK server: {str(e)}")
            exit(2)

def load_groups(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(GROUPS_PATH) and not no_cache:
        logger.info("Loading groups from local JSON file.")
        return load_json(GROUPS_PATH)
    else:
        logger.info("Retrieving all groups from ATT&CK server")
        try:
            lift = attack_client()
            all_groups = lift.get_groups()
            all_groups = serialize_groups(all_groups)
            with open(GROUPS_PATH, 'w+') as json_file:
                json.dump(all_groups, json_file)
            logger.info(f"Groups saved to {GROUPS_PATH}")
            return all_groups
        except Exception as e:
            logger.error(f"Could not download groups from ATT&CK server: {str(e)}")
            exit(2)

def load_mitigations(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(MIT_PATH) and not no_cache:
        logger.info("Loading mitigations from local JSON file.")
        return load_json(MIT_PATH)
    else:
        logger.info("Retrieving all mitigations from ATT&CK server")
        try:
            lift = attack_client()
            all_mitigations = lift.get_mitigations()
            all_mitigations = serialize_mitigations(all_mitigations)
            with open(MIT_PATH, 'w+') as json_file:
                json.dump(all_mitigations, json_file)
            logger.info(f"Mitigations saved to {MIT_PATH}")
            return all_mitigations
        except Exception as e:
            logger.error(f"Could not download mitigations from ATT&CK server: {str(e)}")
            exit(2)

def load_sigma_rules(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(SIGMA_RULES_PATH) and not no_cache:
        logger.info("Loading sigma rules from local JSON file.")
        return load_json(SIGMA_RULES_PATH)
    else:
        logger.info(f"Retrieving all sigma rules from local folder: {SIGMA_RULES_FOLDER}")
        if not os.path.exists(SIGMA_RULES_FOLDER):
            logger.error(f"Sigma rules folder not found: {SIGMA_RULES_FOLDER}")
            return []
        
        all_sigma_rules = []
        for root, _, _ in os.walk(SIGMA_RULES_FOLDER):
            yaml_files = glob.glob(os.path.join(root, '*.yml'))
            logger.info(f"Found {len(yaml_files)} YAML files in {root}")
            for file in yaml_files:
                with open(file, 'r', encoding='utf-8') as stream:
                    try:
                        yaml_data = yaml.safe_load(stream)
                        yaml_data['file'] = file
                        all_sigma_rules.append(yaml_data)
                    except yaml.YAMLError as exc:
                        logger.error(f"Error parsing YAML file {file}: {exc}")
        
        logger.info(f"Total Sigma rules loaded: {len(all_sigma_rules)}")
        all_sigma_rules_sanitized = sanitize_keys_in_place(all_sigma_rules)
        with open(SIGMA_RULES_PATH, 'w+', encoding='utf-8') as json_file:
            json.dump(all_sigma_rules_sanitized, json_file)
        logger.info(f"All sigma rules saved to {SIGMA_RULES_PATH}")
        return all_sigma_rules_sanitized

def load_guardsight(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(GUARDSIGHT_RESPONSES_PATH) and not no_cache:
        logger.info("Loading guardsight responses from local JSON file.")
        return load_json(GUARDSIGHT_RESPONSES_PATH)
    else:
        logger.info(f"Retrieving all guardsight responses from local folder: {GUARDSIGHT_RESPONSES_FOLDER}")
        if not os.path.exists(GUARDSIGHT_RESPONSES_FOLDER):
            logger.error(f"Guardsight responses folder not found: {GUARDSIGHT_RESPONSES_FOLDER}")
            return []
        
        all_guardsight_responses = []
        for root, _, _ in os.walk(GUARDSIGHT_RESPONSES_FOLDER):
            md_files = glob.glob(os.path.join(root, '*.md'))
            logger.info(f"Found {len(md_files)} markdown files in {root}")
            for file in md_files:
                with open(file, 'r', encoding='utf-8') as stream:
                    markdown_content = stream.read()
                    parsed_json = extract_data_from_markdown(markdown_content)
                    if parsed_json:
                        all_guardsight_responses.append(parsed_json)
                    else:
                        logger.warning(f"Failed to extract data from {file}")
        
        logger.info(f"Total Guardsight responses loaded: {len(all_guardsight_responses)}")
        with open(GUARDSIGHT_RESPONSES_PATH, 'w+', encoding='utf-8') as json_file:
            json.dump(all_guardsight_responses, json_file)
        logger.info(f"All guardsight rules saved to {GUARDSIGHT_RESPONSES_PATH}")
    
    return all_guardsight_responses

def load_atomic_tests(no_cache: bool) -> List[Dict[str, Any]]:
    if os.path.exists(ATOMIC_TEST_PATH) and not no_cache:
        logger.info("Loading atomic red tests from local JSON file.")
        return load_json(ATOMIC_TEST_PATH)
    else:
        logger.info(f"Retrieving all atomic red tests from local folder: {ATOMIC_FOLDER}")
        if not os.path.exists(ATOMIC_FOLDER):
            logger.error(f"Atomic tests folder not found: {ATOMIC_FOLDER}")
            return []
        
        all_atomic_tests = []
        for root, dirs, _ in os.walk(ATOMIC_FOLDER):
            dirs[:] = [d for d in dirs if d.startswith('T')]
            yaml_files = glob.glob(os.path.join(root, '*.yaml'))
            logger.info(f"Found {len(yaml_files)} YAML files in {root}")
            for file in yaml_files:
                with open(file, 'r', encoding='utf-8') as stream:
                    try:
                        yaml_data = yaml.safe_load(stream)
                        all_atomic_tests.append((file, yaml_data))
                    except yaml.YAMLError as exc:
                        logger.error(f"Error parsing YAML file {file}: {exc}")
        
        logger.info(f"Total Atomic tests loaded: {len(all_atomic_tests)}")
        with open(ATOMIC_TEST_PATH, 'w+', encoding='utf-8') as json_file:
            json.dump(all_atomic_tests, json_file)
        logger.info(f"All atomic red tests saved to {ATOMIC_TEST_PATH}")
        return all_atomic_tests

def load_all_data(no_cache: bool) -> Dict[str, Any]:
    return {
        'techniques': load_techniques(no_cache),
        'relationships': load_relationships(no_cache),
        'groups': load_groups(no_cache),
        'mitigations': load_mitigations(no_cache),
        'sigma_rules': load_sigma_rules(no_cache),
        'atomic_tests': load_atomic_tests(no_cache),
        'guardsight_responses': load_guardsight(no_cache)
    }

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
            elif 'url' in ref:
                references.append(format_markdown_link(ref['url']))
            elif 'description' in ref:
                references.append(format_markdown_link(ref['description']))
                
            
        serialized.append({
            "type": serialized_t['type'],
            "id": serialized_t['id'],
            "technique_id": serialized_t['external_references'][0]['external_id'],
            "parent_id": serialized_t['external_references'][0]['external_id'].split('.')[0] if '.' in serialized_t['external_references'][0]['external_id'] else None,
            "kill_chain_phases": serialized_t['kill_chain_phases'],
            "name": serialized_t['name'],
            "description": description,
            "all_references": references,
            "group_references": [],
            "usage_references": [],
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