import json
import os
from typing import Dict, Any, List, Optional as OptionalType
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def export_json(data: Dict[str, Any], file_path: str):
    """
    Export data to a JSON file.
    """
    try:
        with open(file_path, 'w+') as json_file:
            json.dump(data, json_file, indent=2)
        logger.info(f"Data exported successfully to {file_path}")
    except IOError as e:
        logger.error(f"Error exporting data to {file_path}: {str(e)}")

def create_export_object(techniques: List[Dict[str, Any]], 
                         interrelation_keywords_and_groups: str,
                         keywords: List[str],
                         interrelation_keywords: str,
                         groups: List[str],
                         interrelation_groups: str,
                         stats: Dict[str, Any],
                         use_cache: bool,
                         filename: str) -> Dict[str, Any]:
    """
    Create the export object containing all relevant information.
    """
    return {
        "interrelation_keywords_and_groups": interrelation_keywords_and_groups,
        "keywords": keywords,
        "interrelation_keywords": interrelation_keywords,
        "groups": groups,
        "interrelation_groups": interrelation_groups,
        "techniques": techniques,
        "stats": stats,
        "created": datetime.now().timestamp(),
        "use_cache": use_cache,
        "filename": filename,
        "id": filename.split(".json")[0]
    }

def export_data(analyzed_data: Dict[str, Any], 
                keywords: OptionalType[List[str]],
                groups: OptionalType[List[str]],
                interrelation_keywords_and_groups: str,
                interrelation_keywords: str,
                interrelation_groups: str,
                no_cache: bool,
                output_path: OptionalType[str] = None,
                full_mapping: bool = False):
    
    if full_mapping:
        logger.info("Full mapping export")
        output_path = "/app/scripts/framework/cache/full_mapping.json"

    if not output_path:
        logger.error("No output path found")
        exit(-1)

    # Ensure output directories exist
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    export_object = create_export_object(
        analyzed_data['techniques'],
        interrelation_keywords_and_groups,
        keywords or [],
        interrelation_keywords,
        groups or [],
        interrelation_groups,
        analyzed_data['overall_stats'],
        not no_cache,
        os.path.basename(output_path)
    )

    # Export main data
    export_json(export_object, output_path)
    
    logger.info("Data export completed successfully")