import os
import json
import logging
import argparse
from data_loader import load_all_data, load_groups
from data_mapper import map_all_data
from data_filter import filter_data
from data_analyzer import analyze_data
from data_exporter import export_data
from config import setup_logging
from utils import remove_technique_duplicates

def load_cached_full_mapping(full_mapping_path):
    if os.path.exists(full_mapping_path):
        with open(full_mapping_path, 'r') as json_file:
            return json.load(json_file)
    return None

def main(args):
    setup_logging()
    logger = logging.getLogger(__name__)

    full_mapping_path = "cache/full_mapping.json"

    if args.fullmapping:
        args.nocache = True
        logger.info("Full mapping requested. Cache will not be used.")

    logger.info("Starting data processing")
    all_data = None
    if not args.fullmapping and not args.nocache:
        cached_data = load_cached_full_mapping(full_mapping_path)
        if cached_data:
            logger.info("Using cached full mapping data")
            mapped_data = cached_data['techniques']
        else:
            logger.info("No cached full mapping found. Processing all data.")
            all_data = load_all_data(args.nocache)
            mapped_data = map_all_data(all_data)
    else:
        all_data = load_all_data(args.nocache)
        mapped_data = map_all_data(all_data)
    
    if not all_data:
        all_groups = load_groups(args.nocache)
    else:
        all_groups = all_data['groups']
    all_techniques_length = len(mapped_data)
    filtered_data = remove_technique_duplicates(mapped_data)
    filtered_data = filter_data(filtered_data, 
                                args.keywords or None,
                                args.groups or None,
                                args.interrelationkeywords, 
                                args.interrelationgroups,
                                args.interrelationkeywordsandgroups,
                                all_groups)
    analyzed_data = analyze_data(filtered_data, all_techniques_length)
    
    export_data(analyzed_data, 
                args.keywords or None,
                args.groups or None,
                args.interrelationkeywordsandgroups,
                args.interrelationkeywords,
                args.interrelationgroups,
                args.nocache,
                args.outputpath,
                args.fullmapping)

    # If we've just created a full mapping, save it to the cache
    if args.fullmapping:
        logger.info("Saving full mapping to cache")
        with open(full_mapping_path, 'w') as json_file:
            json.dump({"techniques": mapped_data}, json_file)

    logger.info("Data processing completed")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ATT&CK data processor")
    parser.add_argument('-f', '--fullmapping', action=argparse.BooleanOptionalAction, required=False, default=False)
    parser.add_argument('-ikg','--interrelationkeywordsandgroups', help='Interrelation keywords and groups (AND or OR)', required=False, choices=['AND', 'OR', 'SINGLE'], default="OR", type=str)
    parser.add_argument('-k', '--keywords', nargs='+', help='Keyword(s)', required=False)
    parser.add_argument('-ik', '--interrelationkeywords', choices=['AND', 'OR', 'SINGLE'], default="OR", help='Interrelation keywords')
    parser.add_argument('-g', '--groups', nargs='+', help='Group(s)', required=False)
    parser.add_argument('-ig', '--interrelationgroups', choices=['AND', 'OR', 'SINGLE'], default="OR", help='Interrelation groups')
    parser.add_argument('-n', '--nocache', action='store_true', help='Do not use cached data')
    parser.add_argument('-o', '--outputpath', help='Export path for json', required=False, type=str)

    args = parser.parse_args()
    main(args)