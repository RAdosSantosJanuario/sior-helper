from typing import Dict, Any, List
from collections import defaultdict

def analyze_and_update_techniques(techniques: List[Dict[str, Any]], all_techniques_length: int) -> tuple[Dict[str, Any], List[Dict[str, Any]]]:
    """extracting statistics for techniques

    Args:
        techniques (List[Dict[str, Any]]): all mapped and filtered techniques
        all_techniques_length (int): length of all techniques

    Returns:
        tuple[Dict[str, Any], List[Dict[str, Any]]]: overall stats and all mapped and filtered techniques with statistics 
    """
    total_techniques = len(techniques)
    unique_responses = set()
    unique_detections = set()
    unique_tests = set()

    for technique in techniques:
        tech_detections = defaultdict(int)
        tech_responses = defaultdict(int)
        tech_tests = defaultdict(int)

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
            unique_tests.update(t['id'] for t in tests)

        technique['stats'] = {
            'detections': dict(tech_detections),
            'responses': dict(tech_responses),
            'tests': dict(tech_tests),
            'total_detections': sum(tech_detections.values()),
            'total_responses': sum(tech_responses.values()),
            'total_tests': sum(tech_tests.values())
        }

    overall_stats = {
        "all_techniques": all_techniques_length,
        'total_used_techniques': total_techniques,
        'unique_responses': len(unique_responses),
        'unique_detections': len(unique_detections),
        'unique_tests': len(unique_tests)
    }

    return overall_stats, techniques

def find_color_for_count(colors: Dict[str, Dict[str, str]], count: int) -> str:
    """util function to find color for a specific count

    Args:
        colors (Dict[str, Dict[str, str]]): all colors
        count (int): count

    Returns:
        str: color for that specific count
    """
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

def analyze_data(techniques: List[Dict[str, Any]], all_techniques_length: int) -> Dict[str, Any]:
    overall_stats, updated_techniques = analyze_and_update_techniques(techniques, all_techniques_length)
    
    return {
        "overall_stats": overall_stats,
        "techniques": updated_techniques
    }