from typing import Dict
import markdown2
from bs4 import BeautifulSoup
import re
import json

def markdown_to_html(markdown_text: str) -> str:
    return markdown2.markdown(markdown_text)

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