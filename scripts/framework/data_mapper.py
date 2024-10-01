from typing import Dict, Any, List
import logging
from utils import markdown_to_html, format_markdown_link
import requests

logger = logging.getLogger(__name__)

def_tech_descriptions = {}

def map_relationships_to_techniques(techniques: List[Dict[str, Any]], relationships: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps relationships to techniques

    Args:
        techniques (List[Dict[str, Any]]): base technique dictionary
        relationships (List[Dict[str, Any]]): relationships to be mapped

    Returns:
        List[Dict[str, Any]]: technique dictionary with mapped relationships
    """
    logger.info("mapping relationships to att&ck")
    relationship_map = prepare_relationship_mapping(relationships)
    
    for technique in techniques:
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
                    technique['all_references'].append(map_for_technique)
    return techniques

def map_groups_to_techniques(techniques: List[Dict[str, Any]], groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps groups to techniques

    Args:
        techniques (List[Dict[str, Any]]): base technique dictionary
        groups (List[Dict[str, Any]]): groups to be mapped

    Returns:
        List[Dict[str, Any]]: technique dictionary with mapped groups
    """
    logger.info("mapping groups to att&ck")
    group_map = {group['id']: group for group in groups}
   
    for technique in techniques:
        groups = []
        for relationship in technique['all_references']:
            if 'relationship_type' in relationship:
                if relationship['relationship_type'] == 'uses' and relationship['source_ref'].startswith('intrusion-set'):
                    group_id = relationship['source_ref']
                    if group_id in group_map:
                        group_ref = {
                            "id": group_map[group_id]["id"],
                            "name": group_map[group_id]["name"],
                            "group_id": group_id,
                            "aliases": group_map[group_id].get("aliases", []),
                            "description": group_map[group_id].get("description", "")
                        }
                        groups.append(group_ref)
        technique["group_references"] = groups
    return techniques

def map_mitigations_to_techniques(techniques: List[Dict[str, Any]], mitigations: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps mitigations to techniques

    Args:
        techniques (List[Dict[str, Any]]): base technique dictionary
        mitigations (List[Dict[str, Any]]): mitigations to be mapped

    Returns:
        List[Dict[str, Any]]: technique dictionary with mapped mitigations
    """
    logger.info("mapping mitigations to att&ck")
    mitigation_dict = {mitigation['id']: mitigation for mitigation in mitigations}

    for technique in techniques:
        for tech_mitigation in technique['mitigations']:
            if tech_mitigation['source_ref'] in mitigation_dict:
                tech_mitigation['mitigation_id'] = mitigation_dict[tech_mitigation['source_ref']]['mitigation_id']
            else:
                logger.warning(f"{tech_mitigation['source_ref']} not in mitigation_dict")
    
    return techniques

def map_sigma_rules_to_techniques(techniques: List[Dict[str, Any]], sigma_rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps sigma rules to techniques

    Args:
        techniques (List[Dict[str, Any]]): base technique dictionary
        sigma_rules (List[Dict[str, Any]]): sigma rules to be mapped

    Returns:
        List[Dict[str, Any]]: technique dictionary with mapped sigma rules
    """
    logger.info("mapping sigma to att&ck")
    for technique in techniques:
        for sigma_detection_rule in sigma_rules:
            if "tags" not in sigma_detection_rule:
                logger.debug("Could not find tag in sigma detection rule")
                continue
                
            for tag in sigma_detection_rule['tags']:
                if 'attack.' not in tag:
                    logger.debug("Not an attack tag")
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
    return techniques

def map_atomic_tests_to_techniques(techniques: List[Dict[str, Any]], atomic_tests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps atomic tests to techniques

    Args:
        techniques (List[Dict[str, Any]]): base technique dictionary
        atomic_tests (List[Dict[str, Any]]): atomic tests to be mapped

    Returns:
        List[Dict[str, Any]]: technique dictionary with mapped atomic tests
    """
    logger.info("mapping atomic to att&ck")
    techniques_by_id = {technique['technique_id']: technique for technique in techniques}

    for atomic in atomic_tests:
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

    return list(techniques_by_id.values())

def map_guardsight_to_techniques(techniques: List[Dict[str, Any]], guardsight_responses: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Maps iron bow (guardsight) data to techniques

    Args:
        techniques (List[Dict[str, Any]]): base technique dictionary
        guardsight_responses (List[Dict[str, Any]]): iron bow (guardsight) data to be mapped

    Returns:
        List[Dict[str, Any]]: technique dictionary with mapped iron bow (guardsight) data
    """
    logger.info("mapping guardsight to att&ck")
    techniques_by_id = {technique['technique_id']: technique for technique in techniques}

    mitigations_to_techniques = {}
    for technique in techniques:
        for mitigation in technique['mitigations']:
            if 'mitigation_id' in mitigation:
                if mitigation['mitigation_id'] not in mitigations_to_techniques:
                    mitigations_to_techniques[mitigation['mitigation_id']] = []
                mitigations_to_techniques[mitigation['mitigation_id']].append(technique)

    for response in guardsight_responses:
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

    return list(techniques_by_id.values())

def get_description_for_d3fend_technique(def_tech_id):
    """fetching description for d3fend technique

    Args:
        def_tech_id (_type_): id of d3fend technique

    Returns:
        _type_: description of d3fend technique
    """
    url = f"https://d3fend.mitre.org/api/technique/d3f:{def_tech_id}.json"
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        logger.debug(f"No d3fend technique description")
        return None

def get_d3fend_for_attack_techniques(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """fetching d3fend techniques for attack techniques. So this function fetches and maps.

    Args:
        techniques (List[Dict[str, Any]]): attack techniques to be mapped

    Returns:
        List[Dict[str, Any]]: attack techniques with mapped d3fend techniques
    """
    logger.info("Loading and mapping d3fend to att&ck")
    global def_tech_descriptions
    for technique in techniques:
        url = f"https://d3fend.mitre.org/api/offensive-technique/attack/{technique['technique_id']}.json"
        try:
            response = requests.get(url)
            response.raise_for_status()
            d3fend_response = response.json()
            if len(d3fend_response['off_to_def']['results']['bindings']) > 0:
                for binding in d3fend_response['off_to_def']['results']['bindings']:
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
                                        def_tech_authors = def_tech_descriptions[def_tech_id]['references']['@graph'][0].get('d3f:kb-author', '').split(',')
                           
                            
                            description = def_tech_description['d3f:definition']
                            if description:
                                description = markdown_to_html(f"{def_tech_description['d3f:definition']}")
                                
                            response = def_tech_description.get('d3f:kb-article')
                            if response:
                                response = markdown_to_html(response)
                            technique['responses']["d3fend"].append({
                                "title": f"{binding['def_tactic_label']['value']} - {binding['def_tech_label']['value']}" ,
                                "id": f"{def_tech_description['@id']}",
                                "description": description,
                                "response": response,
                                "references": def_tech_references,
                                "authors": def_tech_authors
                            })
        except requests.RequestException as e:
            logger.debug(f"No d3fend attack found on d3fend server for {technique['name']}")
       
    return techniques

def filter_attack_techniques_detection(techniques: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """sets d3fend techniques with Detect type as detection in attack technique

    Args:
        techniques (List[Dict[str, Any]]): attack techniques

    Returns:
        List[Dict[str, Any]]: attack techniques with mapped d3fend techniques
    """
    logger.info("extract d3fend detections to att&ck")
    for technique in techniques:
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
    return techniques



def map_all_data(data: Dict[str, Any]) -> Dict[str, Any]:
    """starting all map functions

    Args:
        data (Dict[str, Any]): loaded data

    Returns:
        Dict[str, Any]: mapped data
    """
    techniques = data['techniques']
    techniques = map_relationships_to_techniques(techniques, data['relationships'])
    techniques = map_groups_to_techniques(techniques, data['groups'])
    techniques = map_mitigations_to_techniques(techniques, data['mitigations'])
    techniques = get_d3fend_for_attack_techniques(techniques)
    techniques = filter_attack_techniques_detection(techniques)
    
    techniques = map_sigma_rules_to_techniques(techniques, data['sigma_rules'])
    techniques = map_atomic_tests_to_techniques(techniques, data['atomic_tests'])
    techniques = map_guardsight_to_techniques(techniques, data['guardsight_responses'])
    
    return techniques

def prepare_relationship_mapping(relationships: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """util function for mapping relationships to techniques

    Args:
        relationships (List[Dict[str, Any]]): all relationships

    Returns:
        Dict[str, List[Dict[str, Any]]]: all relationships with relationship ids as keys
    """
    relationship_map = {}
    for relationship in relationships:
        target_ref = relationship.get("target_ref")
        if target_ref not in relationship_map:
            relationship_map[target_ref] = []
        relationship_map[target_ref].append(relationship)
    return relationship_map