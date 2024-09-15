from typing import Dict, Any, List, Optional as OptionalType
from utils import format_markdown_link

def filter_for_keywords(techniques: List[Dict[str, Any]], keywords: List[str], interrelation: str) -> List[Dict[str, Any]]:
    filtered_techniques = []
    for technique in techniques:
        references = []
        
        descriptions_and_references = []
        
        for ref in technique['all_references']:
            if "description" not in ref or ref['description'] is None:
                continue
            else:
                descriptions_and_references.append({
                    "description": ref['description'].lower(),
                    "reference": {
                        "type": ref.get('type'),
                        "description": ref.get('description')
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

        if (interrelation == "AND" or interrelation == "SINGLE") and all(keyword_in_description.values()):
            for ref_type, desc in unique_references:
                references.append({"type": ref_type, "description": desc})
            technique['usage_references'] = references
            filtered_techniques.append(technique)
        elif interrelation == "OR" and any(keyword_in_description.values()):
            for ref_type, desc in unique_references:
                references.append({"type": ref_type, "description": desc})
            technique['usage_references'] = references
            filtered_techniques.append(technique)

    return filtered_techniques

def filter_for_groups(techniques: List[Dict[str, Any]], groups: List[Dict[str, Any]], interrelation: str) -> List[Dict[str, Any]]:
    filtered_techniques = []
    for technique in techniques:
        current_technique_groups = technique.get('group_references', [])
        matching_groups = [
            group for group in groups
            if any(
                any(alias.lower() == group['name'].lower() for alias in group_ref.get('aliases', []))
                for group_ref in current_technique_groups
            )
        ]

        if interrelation == 'OR':
            if matching_groups:
                filtered_techniques.append(add_group_references(technique, matching_groups))
        else:  # AND or SINGLE
            if len(matching_groups) == len(groups):
                filtered_techniques.append(add_group_references(technique, matching_groups))
    
    return filtered_techniques

def add_group_references(technique: Dict[str, Any], matching_groups: List[Dict[str, Any]]) -> Dict[str, Any]:
    for group in matching_groups:
        for ref in technique.get('group_references', []):
            if group['id'] == ref['id'] and ref not in technique['usage_references']:
                    technique['usage_references'].append(group)
    
    return technique

def merge_filtered_techniques(filtered_techniques_keywords: List[Dict[str, Any]], 
                              filtered_techniques_groups: List[Dict[str, Any]], 
                              interrelation: str) -> List[Dict[str, Any]]:
    dict1 = {obj['id']: obj for obj in filtered_techniques_keywords}
    dict2 = {obj['id']: obj for obj in filtered_techniques_groups}
    
    if interrelation == 'OR':
        combined_dict = {**dict1, **dict2}
        return list(combined_dict.values())
    else:  # AND or SINGLE
        common_keys = dict1.keys() & dict2.keys()
        return [dict1[key] for key in common_keys]

def filter_data(techniques: List[Dict[str, Any]], 
                keywords: OptionalType[List[str]], 
                groups: OptionalType[List[str]], 
                keyword_interrelation: str, 
                group_interrelation: str, 
                interrelation_keywords_and_groups: str,
                all_groups: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    if keywords:
        filtered_techniques_keywords = filter_for_keywords(techniques, keywords, keyword_interrelation)
    else:
        filtered_techniques_keywords = techniques

    if groups:
        group_dict = {group['name']: group for group in all_groups}
        full_groups = [group_dict[name] for name in groups if name in group_dict]
        filtered_techniques_groups = filter_for_groups(techniques, full_groups, group_interrelation)
    else:
        filtered_techniques_groups = techniques

    if keywords and groups:
        return merge_filtered_techniques(filtered_techniques_keywords, filtered_techniques_groups, interrelation_keywords_and_groups)
    elif keywords:
        return filtered_techniques_keywords
    elif groups:
        return filtered_techniques_groups
    else:
        return techniques