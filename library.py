from bs4 import BeautifulSoup
from openai import OpenAI
from config import AppConfig
import json
import requests
import regex as re
from vertexai.generative_models import (
    GenerationConfig,
    GenerativeModel,
    HarmBlockThreshold,
    HarmCategory,
)

# # Define project information
PROJECT_ID = AppConfig.Google_PROJECT_ID
LOCATION = AppConfig.LOCATION
MODEL_ID = AppConfig.GEMINI_MODEL
model = GenerativeModel(MODEL_ID)
client = OpenAI(api_key=AppConfig.OPENAI_API_KEY)


def get_vulnerability_prompt(pages_content: str) -> str:
    """
    Generates the common prompt for extracting vulnerability-related information.
    """
    return f"""
        Extract the following information from the CVE description:

        1. Git fix commit hash or fix commit link that fixes the vulnerability. Make sure the fix commit is a link, not just a hash. Also mention the pull request link that fixes the vulnerability, if it exists. If no such information is available, reply 'None'. Name the key as "fix_commit".

        2. Fixed version after the fix/patches commit is applied, no other words should be included with version. Return in a list format, if available; otherwise reply 'None'. If more than one version is returned, order them from lowest to highest version number. Name the list as "fixed_versions".

        3. Confirm whether a fix for the vulnerability exists. Reply with 'Yes' if the fix is mentioned, otherwise reply 'No'. Name the key as "fix_exists".

        4. Briefly describe the vulnerability along with the CVE ID. Ensure the CVE ID is included in the description. Name the key as "vulnerability_details".

        5. Based on the provided data, extract the vulnerable source files, vulnerable functions by considering the CVE ID. Name the key as "vulnerable_artifacts".

        6. Based on the provided data, extract the project repo URL (e.g., GitHub project URL or any other URL pointing to the open-source project URL). Name the key as "repo". If no project URL is available, reply "None".

        Please provide the response in the form of a Python dictionary. It should begin with "{{" and end with "}}".
        The dictionary should have the following keys: "fix_commit", "fixed_versions", "fix_exists", "vulnerability_details", "vulnerable_artifacts", and "repo". The response should not have any markdown delimiters. Just dictionary string is needed.

        Git content: "{pages_content}"
    """


def gemini_generate_vulnerability_response(pages_content: str):
    """
    This function takes a user input prompt and returns the AI-generated response
    relevant to software vulnerability management, including finding fix commits.
    """

    # Set the model's system instructions
    example_model = GenerativeModel(
        MODEL_ID,
        system_instruction=[
            "You are an expert Software Vulnerability Management Analyst.",
            "Your mission is to identify, assess, and prioritize software vulnerabilities in systems.",
            "You should answer the questions asked in the prompt relevant to identification of fix/patch commits,"
            " vulnerable files and functions, and other vulnerability relevant information.",
        ],
    )

    # Set model parameters
    gemini_generation_config = GenerationConfig(
        temperature=0.2,
        top_p=1.0,
        top_k=32,
        candidate_count=1,
        max_output_tokens=8192,
    )

    # Set safety settings (turned off)
    safety_settings = {
        HarmCategory.HARM_CATEGORY_HARASSMENT: HarmBlockThreshold.OFF,
        HarmCategory.HARM_CATEGORY_HATE_SPEECH: HarmBlockThreshold.OFF,
        HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT: HarmBlockThreshold.OFF,
        HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT: HarmBlockThreshold.OFF,
    }

    prompt_text = get_vulnerability_prompt(pages_content)

    # Prompt the model to generate content
    response = example_model.generate_content(
        prompt_text,
        generation_config=gemini_generation_config,
        safety_settings=safety_settings,
    )

    # Return the model's response
    return response.text


def openai_generate_vulnerability_response(pages_text):
    prompt = get_vulnerability_prompt(pages_text)

    # Call the OpenAI API
    response = client.chat.completions.create(model="gpt-4-turbo", temperature=0.1,
                                              messages=[
                                                  {"role": "system", "content": "You are a helpful assistant."},
                                                  {"role": "user", "content": prompt}
                                              ],
                                              max_tokens=500)

    # Extract the response
    # Make sure you do not return date, hash or any other text other than the version number.
    extracted_info = response.choices[0].message.content
    return extracted_info


def post_process_llm_generated_content(text):
    """
    Extracts fix commit hash and PR URL from LLM-generated text.

    Args:
    text (str): The LLM-generated output content.

    Returns:
    dict: A dictionary containing the 'fix_commit' and 'pr_url' (if found).
    """
    result = {
        'fix_commit': None,
        'pr_url': None
    }

    # Regex pattern for identifying commit hashes (short 7-character or full 40-character hashes)
    commit_hash_pattern = r'\b([a-f0-9]{7,40})\b'

    # Look for PR URLs (GitHub PR URLs format)
    pr_url_pattern = r'https://github\.com/[^/]+/[^/]+/pull/\d+'

    # Search for commit hash
    commit_hash_match = re.search(commit_hash_pattern, text)
    if commit_hash_match:
        result['fix_commit'] = commit_hash_match.group(1)

    # Search for PR URL
    pr_url_match = re.search(pr_url_pattern, text)
    if pr_url_match:
        result['pr_url'] = pr_url_match.group(0)

    return result


def process_github_references_prober(references, github_token):
    analysed_pages = set()
    pages_text = []
    links = []
    general_references = {}

    for reference in references:

        if isinstance(reference, dict):
            url = reference.get("url", "")
        elif isinstance(reference, str):
            url = reference

        if match := re.match(r"https://github\.com/(?P<author>.+?)/(?P<repo>.+?)/(issues|pull)/(?P<number>\d+)", url):
            author, repo_name, issue_or_pr, number = match.groups()

            if url in analysed_pages:
                continue

            if issue_or_pr == "issues":
                print("issues", url)
                issue_title, issue_body, comments, commit_info = get_github_data(url, github_token)
                referenced_urls = get_events_from_issue(github_token, author, repo_name, number)

                pages_text.extend([issue_title, issue_body, comments, commit_info])
                links.extend(referenced_urls)
                analysed_pages.add(url)
                analysed_pages.update(referenced_urls)

            elif issue_or_pr == "pull":
                print("pull", url)
                print(author, repo_name, issue_or_pr)

                pr_details = extract_github_pr_details(url)
                if pr_details:
                    owner, repo, pr_number = pr_details

                    pr_details = fetch_github_pr_details(owner, repo, pr_number, github_token)

                    print("Pull Request Body:")
                    print(pr_details["pr_body"])

                    print("\nIssue Comments:")
                    for comment in pr_details["issue_comments"]:
                        print(f"- {comment}")

                    print("\nReview Comments:")
                    for comment in pr_details["review_comments"]:
                        print(f"- {comment}")

                    print("\nCommit Hashes:")
                    for sha in pr_details["commit_hashes"]:
                        print(f"- {sha}")

                    pages_text.append(pr_details["pr_body"])
                    pages_text.append(pr_details["issue_comments"])
                    pages_text.append(pr_details["review_comments"])
                    pages_text.append(pr_details["commit_hashes"])

                    analysed_pages.add(url)

        # elif re.match(r"https://.+\.github\.com(/.*)?", url):  # Process GitHub Pages
        elif re.match(r"https://github\.com(/.*)?", url):  # GitHUb pages inlucluing comments but not PR/issues
            if re.search(r"github\.com/.+/(issues|pull)/\d+", url):
                print(f"Skipping GitHub Issue/PR: {url}")
            else:
                page_content = fetch_page_content(url)
                if page_content:
                    pages_text.append(page_content)
                    analysed_pages.add(url)
        elif "github.com" not in url:
            # General reference processing (non-GitHub)
            page_content = fetch_page_content(url)
            if page_content:
                pages_text.append(page_content)
                analysed_pages.add(url)

    return pages_text, links, analysed_pages, general_references


def extract_github_pr_details(url):
    """
    Extracts the owner, repository name, and pull request number from a GitHub PR URL.

    :param url: GitHub PR URL (e.g., https://github.com/owner/repo/pull/123)
    :return: Tuple (owner, repo, pr_number) or None if URL is invalid
    """
    pattern = r"https://github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<pr_number>\d+)"
    match = re.match(pattern, url)

    if match:
        return match.group("owner"), match.group("repo"), int(match.group("pr_number"))
    else:
        print("Invalid GitHub PR URL format.")
        return None


def fetch_github_pr_details(owner, repo, pr_number, github_token):
    """
    Fetches the pull request body, all comments, and associated commit hashes.

    :param owner: GitHub repository owner
    :param repo: GitHub repository name
    :param pr_number: Pull request number
    :param github_token: GitHub personal access token
    :return: Dictionary containing PR body, comments, and commit hashes
    """
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    base_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}"
    print(base_url)

    # 1. Fetch PR body
    pr_body = None
    pr_response = requests.get(base_url, headers=headers)
    if pr_response.status_code == 200:
        pr_data = pr_response.json()
        pr_body = pr_data.get("body", "").strip()
    else:
        print(f"Failed to fetch PR details: {pr_response.status_code}, {pr_response.text}")

    # 2. Fetch PR issue comments (from Issues API)
    issue_comments_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/comments"
    issue_comments = fetch_paginated_results(issue_comments_url, headers, "body")

    # 3. Fetch PR review comments (from Reviews API)
    review_comments_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/comments"
    review_comments = fetch_paginated_results(review_comments_url, headers, "body")

    # 4. Fetch PR commit hashes
    commits_url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/commits"
    commit_hashes = fetch_paginated_results(commits_url, headers, "sha")

    return {
        "pr_body": pr_body,
        "issue_comments": issue_comments,
        "review_comments": review_comments,
        "commit_hashes": commit_hashes
    }


def fetch_paginated_results(url, headers, key):
    """
    Fetches paginated GitHub API results.

    :param url: API URL
    :param headers: Headers for authentication
    :param key: Key to extract from JSON response
    :return: List of extracted values
    """
    results = []
    while url:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            data = response.json()
            results.extend([item.get(key, "").strip() for item in data if key in item])
            # Get the next page URL if pagination is present
            url = get_next_page_url(response)
        else:
            print(f"Failed to fetch data from {url}: {response.status_code}, {response.text}")
            break
    return results


def get_next_page_url(response):
    """
    Extracts the next page URL from GitHub API response headers.

    :param response: Requests response object
    :return: Next page URL or None
    """
    link_header = response.headers.get("Link", "")
    if link_header:
        links = {rel.split("=")[1]: url.strip("<>") for url, rel in
                 [link.split("; ") for link in link_header.split(", ")]}
        return links.get('"next"')
    return None


def fetch_pull_request_merge_commit(url, github_token):
    """
    Fetches the merge commit SHA of a GitHub pull request.

    :param url: The GitHub API URL of the pull request.
    :param github_token: The GitHub personal access token.
    :return: The merge commit SHA if available, else None.
    """
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raises an error for 4xx/5xx responses

        pr_data = response.json()

        # Ensure the response contains the expected key
        if isinstance(pr_data, dict) and "merge_commit_sha" in pr_data:
            return pr_data["merge_commit_sha"]

        print(f"Unexpected response format: {pr_data}")
        return None

    except requests.exceptions.RequestException as e:
        print(f"GitHub API request error: {e}")
        return None


def fetch_page_content(url):
    try:
        response = requests.get(url, timeout=5)  # Add timeout to avoid hanging
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract all visible text (you could fine-tune this based on your needs)
            visible_text = soup.get_text(separator="\n", strip=True)

            if visible_text:
                return visible_text
            else:
                print("No visible text found on the page.")
                return None
        else:
            print(f"Failed to fetch page: {url}, Status Code: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request error for {url}: {e}")
    return None


def get_cve_desc(cve_id):
    osv_schema = get_osv_schema(cve_id)
    if not osv_schema:
        print(f"No OSV entry for {cve_id}.")
        return None, None, f"No OSV entry for {cve_id}."

    # Extract CVE description
    cve_desc = osv_schema['details']
    git_repo_url = get_repo(osv_schema)

    return cve_desc, git_repo_url, osv_schema['affected']


def get_repo(schema):
    repo = None
    for affected in schema['affected']:
        for ran in affected['ranges']:
            if ran['type'] == 'GIT':
                repo = ran['repo']

    return repo


def get_repo_osv(schema):
    repo = None
    for affected in schema['affected']:
        for ran in affected['ranges']:
            if ran['type'] == 'GIT':
                repo = ran['repo']

    return repo


def get_osv_schema(cve_id):
    api_url = f"https://api.osv.dev/v1/vulns/{cve_id}"
    response = requests.get(api_url)

    # Check if the request was successful
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()
        return data
    else:
        # Handle the error
        print(f"Error: {response.status_code} - {response.text}")
        return None


def extract_fixed_values(data):
    fixed_values = []
    last_affected = None
    fix_found = False
    # Loop through each item in the list
    for item in data:
        # Loop through each range in the 'ranges' list
        for rng in item.get('ranges', []):
            # Loop through each event in the 'events' list
            for event in rng.get('events', []):
                # Check if 'fixed' key is in the event
                if 'fixed' in event:
                    fixed_values.append(event['fixed'])
                    fix_found = True
                if 'last_affected' in event:
                    last_affected = event['last_affected']

    return fix_found, set(fixed_values), last_affected


def process_llm_results(llm_res, dictionary_pattern):
    try:
        # Search for the dictionary pattern in the LLM results
        match = re.search(dictionary_pattern, llm_res, re.DOTALL)
        if match:
            content = match.group(0)
        else:
            print("No match found for the pattern. Continuing to next result.")
            return 0

        # Parse the result to JSON
        parsed_result = json.loads(content)
        return parsed_result
    except json.JSONDecodeError as e:
        print("Error parsing output from LLM:", e)


def extract_cve_data(cve_id):
    """
    Extracts the CVE description and full GitHub URLs for a given CVE ID from NVD API response.
    """
    nvd_api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"

    try:
        # Send request to NVD API
        response = requests.get(nvd_api_url)
        response.raise_for_status()  # Raise exception for bad status codes
        data = response.json()

        # Check if vulnerabilities exist in the response
        if "vulnerabilities" in data and data["vulnerabilities"]:
            cve_item = data["vulnerabilities"][0]["cve"]

            # Extract description
            descriptions = cve_item.get("descriptions", [])
            description = ""
            for desc in descriptions:
                if desc.get("lang") == "en":  # Extract the English description
                    description = desc.get("value", "")

            # Extract GitHub URLs from references (no need to modify URLs)
            github_urls = [
                ref["url"] for ref in cve_item.get("references", [])
                if "github.com" in ref["url"]
            ]

            # Return description and full GitHub URLs
            return description, github_urls if github_urls else None
        else:
            print(f"No CVE entry found for {cve_id}")
            return None, None
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data for {cve_id}: {e}")
        return None, None
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON for {cve_id}: {e}")
        return None, None


def get_events_from_issue(github_token, owner, repo, issue_number):
    # headers = {"Authorization": f"token {github_token}"}
    # headers = {'Accept': 'application/vnd.github.v3+json'}
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.mockingbird-preview+json"
    }
    url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/timeline"
    references = []
    response = requests.get(url, headers=headers)

    if response.status_code != 200:
        print(f"Error: Unable to fetch timeline (Status {response.status_code})")
        return []

    timeline_events = response.json()

    for event in timeline_events:
        if event.get("event") == "cross-referenced" or event.get("event") == "referenced" or event.get(
                "event") == "closed":
            if "commit_id" in event and event['commit_id'] is not None:
                references.append(f"https://github.com/{owner}/{repo}/commit/{event['commit_id']}")
            elif "source" in event and "issue" in event["source"]:
                references.append(event["source"]["issue"]["html_url"])

    return references


def parse_issue_url(issue_url):
    # Regular expression to extract owner, repo, and issue number
    pattern = r"https://github.com/([^/]+)/([^/]+)/issues/(\d+)"
    match = re.match(pattern, issue_url)

    if match:
        repo_owner = match.group(1)
        repo_name = match.group(2)
        issue_number = int(match.group(3))
        return repo_owner, repo_name, issue_number
    else:
        print("Invalid GitHub issue URL.")
        return None, None, None


def parse_github_url(url):
    """Parses a GitHub URL to extract owner, repo, and relevant number/identifier (issue, pull request, or commit)."""
    parts = url.rstrip('/').split('/')
    if len(parts) < 5:
        return None, None, None

    repo_owner = parts[3]
    repo_name = parts[4]

    # Detect if it's an issue, pull request, or commit
    if 'issues' in parts:
        issue_number = parts[-1]
        return repo_owner, repo_name, issue_number, 'issue'
    elif 'pull' in parts:
        pr_number = parts[-1]
        return repo_owner, repo_name, pr_number, 'pr'
    elif 'commit' in parts:
        commit_sha = parts[-1]
        return repo_owner, repo_name, commit_sha, 'commit'
    else:
        return None, None, None, None


def get_commit_details(repo_owner, repo_name, commit_sha, token):
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commits/{commit_sha}"
    headers = {"Accept": "application/vnd.github.v3+json"}

    if token:
        headers["Authorization"] = f"token {token}"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        commit_data = response.json()
        commit_info = {
            "sha": commit_sha,
            "message": commit_data.get("commit", {}).get("message", ""),
            "files": [],
        }

        for file in commit_data.get("files", []):
            commit_info["files"].append({
                "filename": file["filename"],
                "patch": file.get("patch", "No patch available")
            })

        return commit_info

    else:
        print(f"Error: Unable to fetch commit {commit_sha}. Status Code: {response.status_code}")
        return None


def get_github_data(url, token):
    repo_owner, repo_name, identifier, data_type = parse_github_url(url)
    if not repo_owner:
        print("Invalid URL format")
        return None, None, None, None

    headers = {'Accept': 'application/vnd.github.v3+json'}
    if token:
        headers['Authorization'] = f"token {token}"

    if data_type == 'issue':
        # GitHub API URL for getting issue details
        api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{identifier}"
        comments_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/issues/{identifier}/comments"

        # Fetch issue details
        issue_response = requests.get(api_url, headers=headers)
        if issue_response.status_code != 200:
            print(f"Failed to fetch issue details: {issue_response.status_code}")
            return None, None, None, None

        issue_data = issue_response.json()
        issue_title = issue_data['title']
        issue_body = issue_data['body']

        # Fetch comments for the issue
        comments_response = requests.get(comments_url, headers=headers)
        if comments_response.status_code != 200:
            print(f"Failed to fetch comments: {comments_response.status_code}")
            return issue_title, issue_body, None, None
        # comments_data = comments_response.json()
        # comments = [comment['body'] for comment in comments_data]
        try:
            comments_data = comments_response.json()

            # Ensure it's a list before iterating
            if isinstance(comments_data, list):
                comments = [comment['body'] for comment in comments_data if
                            isinstance(comment, dict) and 'body' in comment]
            else:
                print("Unexpected response format: comments_data is not a list")
                comments = None

        except ValueError as e:
            print(f"Failed to parse JSON response: {e}")
            comments = None

        return issue_title, issue_body, comments, None

    elif data_type == 'pr':
        # GitHub API URL for getting pull request details
        api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/pulls/{identifier}"

        # Fetch pull request details
        pr_response = requests.get(api_url, headers=headers)
        if pr_response.status_code != 200:
            print(f"Failed to fetch pull request details: {pr_response.status_code}")
            return None, None, None, None

        pr_data = pr_response.json()
        pr_title = pr_data['title']
        pr_body = pr_data['body']
        pr_user = pr_data['user']['login']

        merge_commit_sha = pr_data.get("merge_commit_sha", None)
        if merge_commit_sha:
            commit_info_ = get_commit_details(repo_owner, repo_name, merge_commit_sha, token)

        return pr_title, pr_body, pr_user, commit_info_

    elif data_type == 'commit':
        # GitHub API URL for getting commit details
        api_url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/commit/{identifier}"

        commit_info = get_commit_details(repo_owner, repo_name, identifier, token)

        return commit_info, None, None, None

    else:
        print("Unknown data type")
        return None, None, None, None
