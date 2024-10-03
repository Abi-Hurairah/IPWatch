import requests
import json
import sys
import re
from bs4 import BeautifulSoup

def extract_website_content(url):
    try:
        # Send an HTTP GET request to the website with allow_redirects set to True
        response = requests.get(url, allow_redirects=True)

        # Check if the request was successful
        if response.status_code == 200:
            return response.text  # Return the content if successful
        else:
            print(f"Failed to retrieve content for {url}. HTTP Status Code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred while fetching {url}: {e}")
        return None

def format_mitre_id(mitre_id):
    # Check if the MITRE ID contains a dot
    if '.' in mitre_id:
        # Split the ID on the dot and format the URL accordingly
        main_id, sub_id = mitre_id.split('.')
        return f"https://attack.mitre.org/techniques/{main_id}/{sub_id}/"
    else:
        return f"https://attack.mitre.org/techniques/{mitre_id}/"

def filter_content(html_content):
    # Use BeautifulSoup to parse HTML content
    soup = BeautifulSoup(html_content, 'html.parser')

    # Extract all paragraphs from the content
    paragraphs = soup.find_all('p')

    # Combine the text from paragraphs and clean it
    extracted_text = ' '.join(p.get_text() for p in paragraphs)

    # Optionally, use regex to filter only relevant parts of the content
    filtered_text = re.sub(r'\s+', ' ', extracted_text)  # Replace multiple spaces with a single space
    return filtered_text.strip()

if __name__ == "__main__":
    # Accept MITRE ID(s) as command-line arguments
    if len(sys.argv) < 2:
        print("Usage: python script.py <MITRE.ID>")
        sys.exit(1)

    MITRE_ID = sys.argv[1]

    # User input for MITRE ID(s)
    user_input = MITRE_ID

    # Split user input by commas to handle multiple IDs
    mitre_ids = [mitre_id.strip() for mitre_id in user_input.split(',')]

    # Variable to store all contents
    all_contents = ""

    # Loop through each MITRE ID to extract content
    for mitre_id in mitre_ids:
        # Format the URL based on MITRE ID
        url = format_mitre_id(mitre_id)

        # Extract the website content and store it in a variable
        content = extract_website_content(url)

        # Filter the content for relevant information
        if content:
            filtered_content = filter_content(content)
            all_contents += f"Content for {mitre_id}:\n{filtered_content}\n\n"

    # Optionally print all collected content
    if all_contents:
        #print("All collected content:\n")
        #print(all_contents)

        # Prepare the API request for summarization
        api_url = "http://{OLLAMA IP ADDRESS}:11434/api/generate"
        headers = {"Content-Type": "application/json"}

        data = {
            "model": "llama3.1",
            "prompt": f"Exlain {MITRE_ID}. Create a summary from the content: {all_contents}. Use simplified language that is understandable from someone who does not have a technical background.",
            "stream": False
        }

        response = requests.post(api_url, headers=headers, data=json.dumps(data))

        if response.status_code == 200:
            response_text = response.text
            data = json.loads(response_text)
            actual_response = data["response"]
            print(actual_response)
        else:
            print("Error:", response.status_code, response.text)
    else:
        print("No content retrieved for the provided MITRE IDs.")
