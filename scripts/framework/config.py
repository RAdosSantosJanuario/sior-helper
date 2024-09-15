import os
import logging

# Paths
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CACHE_DIR = os.path.join(BASE_DIR, 'cache')
RES_DIR = os.path.join(BASE_DIR, '..', 'resources')

# Ensure directories exist
for directory in [CACHE_DIR]:
    os.makedirs(directory, exist_ok=True)

# Cache File paths
TECH_PATH = os.path.join(CACHE_DIR, 'all_techniques.json')
RELATIONS_PATH = os.path.join(CACHE_DIR, 'all_relationships.json')
GROUPS_PATH = os.path.join(CACHE_DIR, 'all_groups.json')
MIT_PATH = os.path.join(CACHE_DIR, 'all_mitigations.json')
SIGMA_RULES_PATH = os.path.join(CACHE_DIR, 'all_sigma_detection_rules.json')
GUARDSIGHT_RESPONSES_PATH = os.path.join(CACHE_DIR, 'all_guardsight_responses.json')
ATOMIC_TEST_PATH = os.path.join(CACHE_DIR, 'all_atomic_tests.json')

# External resources
GUARDSIGHT_RESPONSES_FOLDER = os.path.join(RES_DIR, 'gsvsoc_cirt-playbook-battle-cards', 'Markdown')
ATOMIC_FOLDER = os.path.join(RES_DIR, 'atomic-red-team', 'atomics')
SIGMA_RULES_FOLDER = os.path.join(RES_DIR, 'sigma', 'rules')

def setup_logging():
    logging.basicConfig(level=logging.INFO,
                        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        handlers=[logging.StreamHandler()])