import os
import csv
#import torch
#import vertexai
from bs4 import BeautifulSoup
from dotenv import load_dotenv
import tiktoken
#from google.cloud import aiplatform
from openai import OpenAI
#from vertexai.language_models import TextEmbeddingInput, TextEmbeddingModel
#import numpy as np
import logging
#import git
#from google.api_core import exceptions
from app.config import AppConfig
import json
from datetime import datetime
import requests
import regex as re
import subprocess
from typing import List, Optional
from packaging.version import Version
from collections import defaultdict
from vertexai.generative_models import (
    GenerationConfig,
    GenerativeModel,
    HarmBlockThreshold,
    HarmCategory,
)

# Define project information
PROJECT_ID = "sw-supply-chain-sec-dev-1184"
LOCATION = "australia-southeast1"

# Initialize Vertex AI
# vertexai.init(project=PROJECT_ID, location=LOCATION)
# generation_config = GenerationConfig(
#     temperature=0.9,
#     top_p=1.0,
#     top_k=32,
#     candidate_count=1,
#     max_output_tokens=8192,
# )
#
# aiplatform.init(project=PROJECT_ID, location=LOCATION)
#
MODEL_ID = AppConfig.GEMINI_MODEL
model = GenerativeModel(MODEL_ID)


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

    # Set contents to send to the model
    prompt_text = f"""
        Extract the following information from the CVE description:

        1. Git fix commit hash or fix commit link that fixes the vulnerability, also mention the pull request link that fixes the vulnerability, if it exists. If no such information is available, reply 'None'. Name the key as "fix_commit".

        2. Fixed version after the fix/patches commit is applied, no other words should be included with version. Return in a list format, if available; otherwise reply 'None'. If more than one version is returned, order them from lowest to highest version number. Name the list as "fixed_versions".
        3. Confirm whether a fix for the vulnerability exists. Reply with 'Yes' if the fix is mentioned, otherwise reply 'No'. Name the key as "fix_exists".

        4. Briefly describe the vulnerability along with the CVE ID. Ensure the CVE ID is included in the description. Name the key as "vulnerability_details".
        
        5. Based on the provided data, extract the vulnerable source files, vulnerable functions by considering the CVE ID. Name the key as "vulnerable artifacts".

        Please provide the response in the form of a Python dictionary. It should begin with "{{" and end with "}}".
        The dictionary should have the following keys: "fix_commit", "fixed_versions", "fix_exists", "vulnerability_details",  and "vulnerable artifacts". The response should not have any markdown delimiters. Just dictionary string is needed.


        Git content: "{pages_content}"
        """
    contents = [prompt_text]

    # Prompt the model to generate content
    response = example_model.generate_content(
        contents,
        generation_config=gemini_generation_config,
        safety_settings=safety_settings,
    )

    # Return the model's response
    return response.text


def get_git_log_data(repo_path):
    if not os.path.isdir(repo_path):
        raise ValueError(f"The path {repo_path} is not a valid directory.")

    # Change the working directory to the Git repository
    os.chdir(repo_path)

    # Execute the Git command and capture the output
    # command = 'git --no-pager log --all --pretty=format:"%H %ad *:* %d *:* %B" --date=short --decorate=short -p'
    command = 'git --no-pager log --pretty=format:"%H %ad *:* %d *:* %B" --date=short --decorate=short -p'

    result = subprocess.run(command, shell=True, capture_output=True)

    # Decode the output, handling any decoding errors
    output = result.stdout.decode('utf-8', errors='replace')

    # Split the output into lines
    lines = output.splitlines()

    # Initialize variables for storing commit data
    commits = []
    current_commit = None
    diff = []

    # Regular expressions to match commit and diff sections
    commit_pattern = re.compile(r'^([a-f0-9]{7,40}) (\d{4}-\d{2}-\d{2})')
    diff_pattern = re.compile(r'^diff --git a/(.+) b/(.+)')

    # Parse the output
    for line in lines:
        # Check for commit pattern
        commit_match = commit_pattern.match(line)
        if commit_match:
            # Save previous commit if exists
            if current_commit:
                # Append any remaining diff to the current commit
                if diff:
                    current_commit['diffs'].append('\n'.join(diff))
                commits.append(current_commit)

            if "*:*" not in line:
                continue

            # Start a new commit
            current_commit = {
                'hash': commit_match.group(1),
                'date': commit_match.group(2),
                'decorations': line.split("*:*")[1],
                'message': line.split("*:*")[2],
                'diffs': []
            }
            diff = []  # Reset the diff list for the new commit

        elif current_commit and diff_pattern.match(line):
            # Append any existing diff to the current commit
            if diff:
                current_commit['diffs'].append('\n'.join(diff))
                diff = []  # Reset the diff list for the new diff section

            # Start a new diff section
            diff.append(line)

        elif current_commit:
            # Append lines to the current diff section
            diff.append(line)

    # After the loop, append any remaining diff
    if current_commit:
        if diff:
            current_commit['diffs'].append('\n'.join(diff))
        commits.append(current_commit)

    os.chdir("../..")

    # Convert the structured data to JSON for further processing
    json_output = json.dumps(commits, indent=4)
    return json_output


# def process_github_references(data, github_token):
#     analysed_pages = set()
#     pages_text = []
#     links = []
#
#     for reference in data.get("references", []):
#         url = reference.get("url", "")
#
#         if match := re.match(r"https://github\.com/(?P<author>.+?)/(?P<repo>.+?)/(issues|pull)/(?P<number>\d+)", url):
#             author, repo_name, issue_or_pr, number = match.groups()
#
#             if url in analysed_pages:
#                 continue
#
#             if issue_or_pr == "issues":
#                 issue_title, issue_body, comments, commit_info = get_github_data(url, github_token)
#                 referenced_urls = get_events_from_issue(github_token, author, repo_name, number)
#
#                 pages_text.extend([issue_title, issue_body, comments, commit_info])
#                 links.extend(referenced_urls)
#                 analysed_pages.update(referenced_urls)
#
#             elif issue_or_pr == "pull":
#                 merge_commit_sha = fetch_pull_request_merge_commit(url, github_token)
#                 if merge_commit_sha:
#                     print(f"Merge Commit SHA: {merge_commit_sha}")
#                 analysed_pages.add(url)
#
#         elif re.match(r"https://.+\.github\.io(/.*)?", url):  # Process GitHub Pages
#             page_content = fetch_github_page_content(url)
#             if page_content:
#                 pages_text.append(page_content)
#                 analysed_pages.add(url)
#                 print(f"Processed GitHub Page: {url}")
#
#     return pages_text, links, analysed_pages
#
#
# def fetch_pull_request_merge_commit(url, github_token):
#     headers = {"Authorization": f"token {github_token}", "Accept": "application/vnd.github.v3+json"}
#     try:
#         response = requests.get(url, headers=headers)
#         if response.status_code == 200:
#             return response.json().get("merge_commit_sha")
#         print(f"Failed to fetch PR: {response.status_code}, {response.text}")
#     except requests.exceptions.RequestException as e:
#         print(f"GitHub API request error: {e}")
#     return None
#
#
# def fetch_github_page_content(url):
#     try:
#         response = requests.get(url)
#         if response.status_code == 200:
#             return response.text  # Full HTML content, can be parsed further if needed
#         print(f"Failed to fetch GitHub Page: {response.status_code}")
#     except requests.exceptions.RequestException as e:
#         print(f"Request error for GitHub Page: {e}")
#     return None


def process_github_references(data, github_token):
    analysed_pages = set()
    pages_text = []
    links = []
    general_references = {}

    for reference in data.get("references", []):
        url = reference.get("url", "")

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
                print("github.com", url)
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


def extract_upstream_version(version):
    # Regex pattern to match both Debian and normal versions
    match = re.search(r'(?:\d+:)?([0-9.]+)(?:-\d+)?$', version)

    if match:
        return match.group(1)
    return None


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


def extract_most_recent_version(versions_set):
    # Regular expression pattern to match valid version strings
    version_pattern = re.compile(r'^\d+(\.\d+)*(-[a-zA-Z0-9]+)?$')

    # Filter out valid versions using regex
    valid_versions = [v for v in versions_set if version_pattern.match(v)]

    # If no valid versions are found, return None
    if not valid_versions:
        return None

    # Sort the versions using `packaging.version.Version` to compare them
    sorted_versions = sorted(valid_versions, key=lambda v: Version(v), reverse=True)

    # Return the most recent version (the first element in the sorted list)
    return sorted_versions[0]


def extract_and_merge_items(cve_id, output_dir):
    # Get OSV schema
    osv_schema = get_osv_schema(cve_id)
    if not osv_schema:
        print(f"No OSV schema for {cve_id}.")
        return None, None, None, None, None, None, None, None

    # Extract CVE description
    cve_desc = osv_schema['details']
    git_repo_url = get_repo(osv_schema)
    affected = osv_schema['affected']
    try:
        pub_date = datetime.strptime(osv_schema['published'], "%Y-%m-%dT%H:%M:%SZ").date()
    except ValueError as e:
        pub_date = None
        print(e)

    # fix_found, last_affected_commit_hash = get_last_affected(affected)
    fix_found, fixed_vers, last_affected_commit_hash = extract_fixed_values(affected)

    if not git_repo_url:
        repo_path = None
    else:
        repo_path = download_repo(git_repo_url, output_dir)

    # Regex patterns
    patterns = [
        # r'(?:[a-zA-Z]:[\\/]|\/)?(?:[\w-]+[\\/])*[\w-]+\.[\w]+',  # file paths
        # r'[\w-]+\.[\w]+',  # files with extensions
        r'\b[\w-]*_[\w-]*\b',  # words with underscores
        r'\b[\w-]*-[\w-]*\b',  # words with hyphens
        # #r'\b\d+\.\d+(?:\.\d+)?\b',  # versions
        r'\b[A-Z]{2,}\b',  # all caps words
        r"'([^']+)'",  # words within quotes
        r'\b[\w_]+\(\)',  # function calls
    ]

    # Find all matches
    matches = []
    for pattern in patterns:
        matches.extend(re.findall(pattern, cve_desc))

    # Convert to a set to remove duplicates and return as a list
    unique_matches = list(set(matches))

    return unique_matches, repo_path, git_repo_url, fix_found, fixed_vers, last_affected_commit_hash, pub_date, cve_desc


def get_all_tags(r_path):
    """Retrieve all tags from the Git repository."""
    result = subprocess.run(['git', '-C', r_path, 'tag'], stdout=subprocess.PIPE)
    tags = result.stdout.decode('utf-8').split()
    return tags


# def find_closest_tag(tag, tags):
#     """Find the closest matching tag using fuzzy matching."""
#     closest_tag, _ = process.extractOne(tag, tags)
#     return closest_tag


def parse_version(version_str: str) -> List[int]:
    # Extract numeric parts of the version
    return list(map(int, re.findall(r'\d+', version_str)))


def get_closest_version(tags: List[str], target_version: str) -> Optional[str]:
    # Parse the target version
    target_parts = parse_version(target_version)

    # Filter out non-numeric tags
    valid_tags = [tag for tag in tags if parse_version(tag)]

    # If there are no valid tags, return None
    if not valid_tags:
        return None

    def version_distance(tag: str) -> int:
        tag_parts = parse_version(tag)
        # Compute the distance between target and tag versions
        # Pad with zeros for comparison
        max_len = max(len(target_parts), len(tag_parts))
        target_padded = target_parts + [0] * (max_len - len(target_parts))
        tag_padded = tag_parts + [0] * (max_len - len(tag_parts))
        return sum(abs(tp - tg) for tp, tg in zip(target_padded, tag_padded))

    # Find the tag with the minimum distance
    closest_tag = min(valid_tags, key=version_distance)

    return closest_tag


def get_commit_range(repo_path, fuzzy_version1, fuzzy_version2):
    """Print the commit range between two fuzzy-matched versions."""
    # Get all tags
    tags = get_all_tags(repo_path)

    # Get the total number of commits in the repository
    total_commits_command = ['git', '-C', repo_path, 'rev-list', '--all', '--count']
    # total_commits_command = ['git', '-C', repo_path, 'rev-list', '--count']
    total_commits_result = subprocess.run(total_commits_command, stdout=subprocess.PIPE, text=True)
    total_commits = int(total_commits_result.stdout.strip())

    # Find the closest matching tags
    closest_tag1 = get_closest_version(tags, fuzzy_version1)
    closest_tag2 = get_closest_version(tags, fuzzy_version2)

    if closest_tag1 == closest_tag2:
        closest_tag1 = get_previous_version(repo_path, closest_tag1)

    print(f"Closest tag for {fuzzy_version1}: {closest_tag1}")
    print(f"Closest tag for {fuzzy_version2}: {closest_tag2}")

    # Use the closest tags to get the commit range
    # log_command = ['git', '-C', repo_path, 'log', '--oneline', f'{closest_tag1}..{closest_tag2}']
    # log_command = ['git', '-C', repo_path, 'log', '--all', '--format=%H %s', f'{closest_tag1}..{closest_tag2}']
    log_command = ['git', '-C', repo_path, 'log', '--format=%H %s', f'{closest_tag1}..{closest_tag2}']

    commits_range = subprocess.run(log_command, stdout=subprocess.PIPE)

    # Decode and split the output into a list of commits
    commits = commits_range.stdout.decode('utf-8').splitlines()

    return total_commits, commits


def is_valid_git_hash(value):
    """Check if the given value is a valid Git hash."""
    if isinstance(value, str) and re.match(r'^[0-9a-f]{40}$', value):
        return True
    return False


def get_commits_between_last_affected_hashe_n_fixed_version(repo_path, start_hash, fuzzy_version):
    """Return the list of commits between a given Git hash and a fuzzy-matched version tag."""
    # Get all tags
    tags = get_all_tags(repo_path)

    # Find the closest matching tag
    closest_tag = get_closest_version(tags, fuzzy_version)

    print(f"Closest tag for {fuzzy_version}: {closest_tag}")

    # Use the start hash and the closest tag to get the commit range
    log_command = ['git', '-C', repo_path, 'log', '--oneline', f'{start_hash}..{closest_tag}']
    result = subprocess.run(log_command, stdout=subprocess.PIPE)

    # Decode and split the output into a list of commits
    commits = result.stdout.decode('utf-8').splitlines()
    return commits


def get_tag_for_commit(commit_hash, repo_path):
    try:
        # Get the tag relevant to the specific commit
        tag = subprocess.check_output(['git', '-C', repo_path, 'describe', '--tags', commit_hash]).strip().decode(
            'utf-8')
        return tag
    except subprocess.CalledProcessError:
        return None  # If no tag is found


def get_commits_between_last_affected_hash_n_fixed_version(repo_path, start_hash, fuzzy_version):
    """
    Return the list of commits between a given Git hash and a fuzzy-matched version tag,
    along with the total number of commits in the repository, and the number of commits
    between the specified versions.
    """
    # Get all tags
    tags = get_all_tags(repo_path)

    # Find the closest matching tag
    closest_tag = get_closest_version(tags, fuzzy_version)

    print(f"Closest tag for {fuzzy_version}: {closest_tag}")

    # Get the total number of commits in the repository
    total_commits_command = ['git', '-C', repo_path, 'rev-list', '--all', '--count']
    total_commits_result = subprocess.run(total_commits_command, stdout=subprocess.PIPE, text=True)
    total_commits = int(total_commits_result.stdout.strip())

    # Use the start hash and the closest tag to get the commit range
    # log_command = ['git', '-C', repo_path, 'log', '--all', '--oneline', '--format=%H', f'{start_hash}..{closest_tag}']
    log_command = ['git', '-C', repo_path, 'log', '--oneline', '--format=%H', f'{start_hash}..{closest_tag}']
    result = subprocess.run(log_command, stdout=subprocess.PIPE, text=True)

    # Decode and split the output into a list of commits
    commits = result.stdout.splitlines()

    # Get the number of commits between the two versions
    commits_between_versions = len(commits)

    return total_commits, commits_between_versions, commits


def get_commits_between_affected_version_n_fixed_hash(repo_path, start_hash, fuzzy_version):
    """
    Return the list of commits between a given Git hash and a fuzzy-matched version tag,
    along with the total number of commits in the repository, and the number of commits
    between the specified versions.
    """
    # Get all tags
    tags = get_all_tags(repo_path)

    # Find the closest matching tag
    closest_tag = get_closest_version(tags, fuzzy_version)
    closest_tag_fix_hash = get_latest_tag_from_commit(start_hash, repo_path)

    print(f"Closest tag for {fuzzy_version}: {closest_tag}")

    # Get the total number of commits in the repository
    total_commits_command = ['git', '-C', repo_path, 'rev-list', '--all', '--count']
    total_commits_result = subprocess.run(total_commits_command, stdout=subprocess.PIPE, text=True)
    total_commits = int(total_commits_result.stdout.strip())

    # Use the start hash and the closest tag to get the commit range
    # log_command = ['git', '-C', repo_path, 'log', 'all', '--oneline', '--format=%H', f'{closest_tag}..{start_hash}']
    log_command = ['git', '-C', repo_path, 'log', '--oneline', '--format=%H', f'{closest_tag}..{closest_tag_fix_hash}']
    result = subprocess.run(log_command, stdout=subprocess.PIPE, text=True)

    # Decode and split the output into a list of commits
    commits = result.stdout.splitlines()

    # Get the number of commits between the two versions
    commits_between_versions = len(commits)

    return total_commits, commits_between_versions, commits


def get_latest_tag_from_commit(commit_hash, repo_path):
    try:
        # Get the latest tag reachable from the given commit hash
        result = subprocess.run(
            ['git', '-C', repo_path, 'describe', '--tags', '--contains', '--abbrev=0', commit_hash],
            check=True,
            text=True,
            capture_output=True
        )
        tag = result.stdout.strip()
        return tag
    except subprocess.CalledProcessError:
        print(subprocess.CalledProcessError)
        return None


def get_previous_version(path, current_version):
    # Get all tags and sort them using the 'version:refname' sorting option
    # tags = subprocess.check_output(['git', '-C', path, 'tag', '--sort=-v:refname']).decode().splitlines()
    tags = get_all_tags(path)

    # Find the index of the current version
    try:
        closest_tag = get_closest_version(tags, current_version)
        current_index = tags.index(closest_tag)
    except ValueError:
        raise ValueError(f"Version {current_version} not found in tags.")

    # Get the previous version if it exists
    if current_index > 0:
        return tags[current_index - 1]
    else:
        return None  # No previous version found


def get_next_version(path, current_version):
    # Get all tags and sort them using the 'version:refname' sorting option
    # tags = subprocess.check_output(['git', '-C', path, 'tag', '--sort=-v:refname']).decode().splitlines()
    tags = get_all_tags(path)

    # Find the index of the current version
    try:
        closest_tag = get_closest_version(tags, current_version)
        current_index = tags.index(closest_tag)
    except ValueError:
        raise ValueError(f"Version {current_version} not found in tags.")

    # Get the previous version if it exists
    if current_index > 0:
        return tags[current_index + 1]
    else:
        return None  # No previous version found


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


def match_keywords(data, keywords):
    matched_items = {}
    for key, value in data.items():
        # Check if any keyword is in the current value
        if any(keyword.lower() in str(value).lower() for keyword in keywords):
            matched_items[key] = value

    return matched_items


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


def openai_vulnerability_info_extraction(pages_text):
    if not hasattr(genai, "GenerativeModel"):
        raise ImportError(
            "Your installed google-generativeai version does not support GenerativeModel. Please update it.")

    # Initialize Gemini Model
    model = genai.GenerativeModel(model_name="gemini-1.5-flash")

    prompt_text = f"""
    Extract the following information from the CVE description:

    1. Git fix commit hash or fix commit link, also mention the pull request link, if it exists. 
       If no such information is available, reply 'None'. Name the key as "fix_commit".

    2. Fixed version but valid versions, no other words should be included with version. 
       Return in a list format, if available; otherwise reply 'None'. If more than one version is returned, 
       order them from lowest to highest version number. Name the list as "fixed_versions".

    3. Confirm whether a fix for the CVE exists. Reply with 'Yes' if the fix is mentioned, otherwise reply 'No'. 
       Name the key as "fix_exists".

    4. Briefly describe the vulnerability along with the CVE ID. Ensure the CVE ID is included in the description. 
       Name the key as "vulnerability_details".

    Please provide the response in the form of a Python dictionary. It should begin with '{{' and end with '}}'.
    The dictionary should have the following keys: "fix_commit", "fixed_versions", "fix_exists", and "vulnerability_details".
    The response should not have any markdown delimiters. Just dictionary string is needed.

    CVE Description: "{pages_text}"
    """

    response = model.generate_content(prompt_text)

    try:
        response_dict = eval(response.text)  # Convert model output to dictionary
        return response_dict
    except Exception as e:
        print(f"Error parsing response: {e}")
        return None


def get_matched_commits(cve_id, parsed_result, commits, repo_path):
    matched_hashes = []

    # Extract impacted artifacts keywords
    keywords = parsed_result.get('impacted_artifacts', [])
    keywords_set = set(keywords)

    # Initialize counter for matched commits
    matched_commit_count = 0

    # Process each commit to find matches
    for commit in commits:
        matched = match_keywords(commit, keywords_set)
        if matched:
            matched_hashes.append(commit['hash'])
            matched_commit_count += 1

    return matched_hashes


def log_commits_if_repo_changed(repo_path, repo):
    if repo != repo_path:
        repo = repo_path
        content = get_git_log_data(repo_path)
        commits = json.loads(content)
        print("Commits logged........ !")
        return commits, repo

    return repo, None


def extract_commit_hash(url):
    # Define the regex pattern for a GitHub commit URL
    pattern = r"https://github\.com/[^/]+/[^/]+/commit/([0-9a-f]{40})"

    # Search for the pattern in the given URL
    match = re.search(pattern, url)

    # If a match is found, return the hash
    if match:
        return match.group(1)
    else:
        return None


def is_fix_hash_found(commits, fix_hash):
    """
    Check if a target Git commit hash is present in a list of commits.

    Parameters:
    - commits (list of str): List of commit strings obtained from 'git log --oneline'.
    - target_hash (str): The Git commit hash to search for.

    Returns:
    - bool: True if the target hash is found in the commits list, False otherwise.
    """

    # Iterate through the list of commits
    for commit in commits:
        # Split each commit entry to separate the hash from the commit message
        commit_parts = commit.split(maxsplit=1)
        commit_hash = commit_parts[0] if commit_parts else ""

        # Check if the commit hash matches the target hash
        if commit_hash == fix_hash:
            return True

    # If no match is found, return False
    return False


def append_record(file_loc, record):
    with open(file_loc, 'a', newline="", encoding="utf-8") as f:
        f.write(' '.join(str(item) for item in record) + os.linesep)


def get_cve_fix_data(file1_path, file2_path):
    """
    Extracts CVE ID and fix hashes from two files with different formats.

    Args:
      file1_path: Path to the first file (format: CVE-ID hash).
      file2_path: Path to the second file (format: CVE-ID: URL/commit/hash).

    Returns:
      A list of tuples, where each tuple contains (CVE-ID, fix_hash).
    """

    cve_fix_data = []

    # Extract data from file 1
    with open(file1_path, 'r') as f1:
        for line in f1:
            cve_id, fix_hash = line.strip().split()
            cve_fix_data.append((cve_id, fix_hash))

    # Extract data from file 2
    with open(file2_path, 'r') as f2:
        for line in f2:
            cve_id, url = line.strip().split(": ", 1)
            fix_hash = url.split("/")[-1]  # Extract hash from URL
            cve_fix_data.append((cve_id, fix_hash))

    return cve_fix_data


def get_cve_fix_test_data(file1_path):
    """
    Extracts CVE ID and fix hashes from two files with different formats.

    Args:
      file1_path: Path to the first file (format: CVE-ID hash).
      file2_path: Path to the second file (format: CVE-ID: URL/commit/hash).

    Returns:
      A list of tuples, where each tuple contains (CVE-ID, fix_hash).
    """

    cve_fix_data = []

    # Extract data from file 1
    with open(file1_path, 'r') as f1:
        for line in f1:
            cve_id, url = line.strip().split(": ", 1)
            fix_hash = url.split("/")[-1]  # Extract hash from URL
            cve_fix_data.append((cve_id, fix_hash))

    return cve_fix_data


def get_my_test_cves_list(file1_path):
    cve_fix_data = []

    with open(file1_path, 'r') as f1:
        for line in f1:
            cve_id, repo = line.strip().split(" ", 1)
            cve_fix_data.append((cve_id, repo))

    return cve_fix_data


def only_hashes(data):
    # Regex pattern for Git hashes (full 40-character or shorter hexadecimal strings)
    hash_pattern = re.compile(r'^[a-f0-9]{40}$')

    # Check if all entries in the set are hashes
    for entry in data:
        if hash_pattern.match(entry):
            return False
    return True


def get_commit_diff(commit_hash, repo_path):
    diff_data = defaultdict(list)

    def commit_exists(commit):
        try:
            subprocess.check_output(["git", "-C", repo_path, "cat-file", "-e", f"{commit}^{{commit}}"])
            return True
        except subprocess.CalledProcessError:
            return False

    # Verify that the specified commit exists
    if not commit_exists(commit_hash):
        return None
        # raise ValueError(f"Commit hash '{commit_hash}' does not exist in the repository.")

    # Check if the commit is the initial commit
    parent_commit = f"{commit_hash}~1"
    is_initial_commit = not commit_exists(parent_commit)

    # Run the appropriate git diff command
    if is_initial_commit:
        process = subprocess.run(
            ["git", "-C", repo_path, "show", "--pretty=format:", "--name-only", commit_hash],
            capture_output=True,
            text=True,
            errors='ignore'
        )
    else:
        process = subprocess.run(
            ["git", "-C", repo_path, "diff", f"{parent_commit}..{commit_hash}"],
            capture_output=True,
            text=True,
            errors='ignore'
        )

    if process.returncode != 0:
        raise RuntimeError(f"Error running git diff: {process.stderr}")

    current_file = None
    for line in process.stdout.splitlines():
        if line.startswith("--- a/"):
            current_file = line[6:]  # Extract file path after "--- a/"
        elif line.startswith("+++ b/"):
            continue  # Skip "+++ b/" line
        elif current_file and (
                current_file.endswith((".py", ".js", ".php", ".hpp", ".cc", ".java", ".cpp", ".c", ".h", "pl", ".go",
                                       ".rs", ".ctp", ".swift")) or any(
            current_file.endswith(ext) for ext in (".ts", ".tsx", ".jsx"))):
            diff_data[current_file].append(line)

    return diff_data


def get_commit_message(repo_path, commit_hash):
    try:
        commit_msg = subprocess.run(
            ['git', '-C', repo_path, 'show', '-s', '--format=%B', commit_hash],
            capture_output=True,
            text=True
        )
        return commit_msg.stdout.strip()

    except Exception as e:

        return f"Error: {str(e)}"


def get_commit_message_heading(repo_path, commit_hash):
    try:
        commit_msg = subprocess.run(
            ['git', '-C', repo_path, 'show', '-s', '--format=%B', commit_hash],
            capture_output=True,
            text=True
        )
        return commit_msg.stdout.strip()

    except Exception as e:
        return f"Error: {str(e)}"


def preprocess_diff_lines(lines):
    cleaned_lines = []
    for line in lines:
        # Strip leading/trailing whitespace
        line = line.strip()
        # Remove leading '+' or '-' symbols
        if line.startswith('+') or line.startswith('-'):
            line = line[1:]
        # Remove all spaces
        # line = line.replace(' ', '')
        line = line.replace(' ', '').replace('\t', '')
        cleaned_lines.append(line)
    return cleaned_lines


def get_structured_diffed_data(commit_msg, diff):  # , cve, commit):
    # Define regular expression pattern for matching hunk headers and modified lines
    hunk_header_pattern = re.compile(r'^@@\s*-(\d+),?(\d*)\s*\+(\d+),?(\d*)\s*@@.*$')

    current_file = None
    current_hunk_header = None
    hunk_headers = []
    modified_lines = False
    # modified_lines = []
    added_lines = []
    removed_lines = []
    files_hunks = {}

    for file_n, lines in diff.items():
        current_file = file_n
        for line in lines:
            hunk_match = hunk_header_pattern.match(line)
            if hunk_match:
                # If a new hunk header is found, store the previous hunk header and modified lines
                if current_hunk_header and modified_lines:
                    # hunk_headers.append((current_hunk_header, modified_lines))
                    hunk_headers.append((current_hunk_header, added_lines, removed_lines))
                # Initialize for the new hunk header
                current_hunk_header = line.strip()
                # modified_lines = []
                added_lines = []
                removed_lines = []

                if current_file not in files_hunks:
                    files_hunks[current_file] = [current_hunk_header]
                else:
                    files_hunks[current_file].append(current_hunk_header)
            elif line.startswith(('+', '-')) and current_hunk_header:
                if "+++" in line or "---" in line:
                    continue
                # modified_lines.append(line.strip())
                modified_lines = True
                if line.startswith('+'):
                    added_lines.append(line.strip())
                elif line.startswith('-'):
                    removed_lines.append(line.strip())
    # Store the last hunk header and modified lines
    if current_hunk_header and modified_lines:
        hunk_headers.append((current_hunk_header, added_lines, removed_lines))
    diff_info = {}
    for i in files_hunks:
        for j in files_hunks.get(i):
            for k in hunk_headers:
                if j == k[0]:
                    if i not in diff_info:
                        # diff_info[i] = [(j, k[1])]
                        temp = {}
                        temp['hunk_header'] = j
                        temp['added_lines'] = preprocess_diff_lines(k[1])
                        temp['removed_lines'] = preprocess_diff_lines(k[2])
                        diff_info[i] = [temp]
                    else:
                        # diff_info[i].append((j, k[1]))
                        temp = {}
                        temp['hunk_header'] = j
                        temp['added_lines'] = preprocess_diff_lines(k[1])
                        temp['removed_lines'] = preprocess_diff_lines(k[2])
                        diff_info[i].append(temp)
                    _, file_ext = os.path.splitext(i)
    return diff_info


def extract_functions_boundaries(source_file):
    functions = []
    result = subprocess.run(['ctags', '-x', "--sort=no", source_file], check=True, stdout=subprocess.PIPE)
    # with open('/Users/ahm038/PycharmProjects/sscs/tags', 'wb') as f:
    #     f.write(result.stdout)
    lines = result.stdout.decode('iso-8859-1').splitlines()
    for line in lines:
        fields = line.split('\t')
        fields = fields[0].replace("'", "").split()
        if len(fields) >= 5 and fields[1] in ['function', 'member', 'class']:
            # Extract function name and line number
            function_name = fields[0]
            line_number = int(fields[2])
            functions.append((function_name, line_number))

    # with open('/Users/ahm038/PycharmProjects/sscs/tags', 'r', encoding="ISO-8859-1") as tags_file:
    #     for line in tags_file:
    #         fields = line.split('\t')
    #         fields = fields[0].replace("'", "").split()
    #         if len(fields) >= 5 and fields[1] in ['function', 'member', 'class']:
    #             # Extract function name and line number
    #             function_name = fields[0]
    #             line_number = int(fields[2])
    #             functions.append((function_name, line_number))
    return functions


def get_candidate_functions(line_numbers, functions):
    if not line_numbers:
        return None, None
    sorted_data = sorted(functions, key=lambda x: x[1])
    affected_function = None
    func_line_number = None
    for item in sorted_data:
        if line_numbers[len(line_numbers) - 1] > item[1]:  # and line_numbers[0] > item[1]:
            affected_function = item[0]
            func_line_number = item[1]
    return affected_function, func_line_number


def curate_data(fix_hash, data, cve, repo_path):
    functions = {}
    candidate_functions = []
    af_load = False
    b4_load = False
    # Create a list of items to avoid modifying the dictionary during iteration
    items = list(data.items())
    for f, details in items:
        # before_functions, after_functions = get_functions_from_before_and_after_versions(fix_hash, f)
        for det in details:
            modified_af_function = None
            if det['added_lines']:
                af_load = True
                file_path = os.path.join("commits", cve, fix_hash, "after", f)
                file_name = os.path.basename(file_path)
                dir_path = os.path.dirname(file_path)
                os.makedirs(dir_path, exist_ok=True)
                if not os.path.exists(file_path):
                    after_ver = get_file_from_commit(fix_hash, f, repo_path)
                    write_commit_to_file(file_path, after_ver)
                chunk_header = det['hunk_header']
                lines = extract_lines_from_chunk_header(chunk_header)
                if all(element is None for element in lines):
                    functions = None
                    continue
                else:
                    start_line = lines[2]
                    end_line = lines[2] + lines[3]
                functions = extract_functions_boundaries(file_path)
                if start_line and end_line:
                    modified_af_function, can_af_function_line_numbers = get_candidate_functions(
                        list(range(start_line, end_line)), functions)
                    # print("AfterVer", f, chunk_header, modified_af_function, can_af_function_line_numbers)
                    det['modified_func'] = modified_af_function
            modified_b4_function = None
            if det['removed_lines']:
                b4_load = True
                repo = git.Repo(repo_path)
                new_commit = repo.commit(fix_hash)
                parent_commit = new_commit.parents[0]
                # Get file contents from the parent and new commit
                file_path = os.path.join("commits", cve, fix_hash, "before", f)
                file_name = os.path.basename(file_path)
                dir_path = os.path.dirname(file_path)
                os.makedirs(dir_path, exist_ok=True)
                if not os.path.exists(file_path):
                    before_ver = get_file_from_commit(parent_commit.hexsha, f, repo_path)
                    write_commit_to_file(file_path, before_ver)
                chunk_header = det['hunk_header']
                lines = extract_lines_from_chunk_header(chunk_header)
                if all(element is None for element in lines):
                    functions = None
                    continue
                else:
                    start_line = lines[2]
                    end_line = lines[2] + lines[3]
                functions = extract_functions_boundaries(file_path)
                if start_line and end_line:
                    modified_b4_function, can_b4_function_line_numbers = get_candidate_functions(
                        list(range(start_line, end_line)), functions)
                    # print("B4Ver", f, chunk_header, modified_b4_function, can_b4_function_line_numbers)
                    det['modified_func'] = modified_b4_function

            if af_load:
                candidate_functions.append(modified_af_function)
            if b4_load:
                candidate_functions.append(modified_b4_function)
        can_funcs = set(candidate_functions)
        temp = {}
        temp['modifications'] = details
        temp['patch_modified_funcs'] = can_funcs
        data[f] = temp

    return data


def format_data(c_hash, comm_msg, curateddata):
    test_data = []
    temp = {'c_hash': c_hash, 'git_msg': comm_msg, 'modifications': curateddata}
    test_data.append(comm_msg)
    for key, value in curateddata.items():
        test_data.append(key)
        for k, v in value.items():
            test_data.append(k)
            test_data.append(v)
    return temp, test_data


def write_commit_to_file(write_file_path, content):
    if not os.path.exists(write_file_path) and content is not None:
        try:
            with open(write_file_path, 'w') as f:
                f.write(content)  # .encode('utf-8'))
        except IOError as e:
            print(f"Error writing commit file to the disk: {e}")
            return None


def get_file_from_commit(commit_hash, file_path, repo_path):
    repo = git.Repo(repo_path)
    commit = repo.commit(commit_hash)
    try:
        file_content = commit.tree[file_path].data_stream.read()
        try:
            file_content = file_content.decode('utf-8')
        except UnicodeDecodeError:
            # Handle the error (e.g., log it, try a different encoding, return None, etc.)
            print(f"UnicodeDecodeError: 'utf-8' codec can't decode byte in file {file_path} at commit {commit_hash}")
            file_content = None
    except KeyError:
        file_content = None
    return file_content


def extract_lines_from_chunk_header(chunk_header):
    match = re.match(r'@@ -(\d+),(\d+) \+(\d+),(\d+) @@', chunk_header)
    if match:
        start_line_original = int(match.group(1))
        num_lines_original = int(match.group(2))
        start_line_modified = int(match.group(3))
        num_lines_modified = int(match.group(4))
        return start_line_original, num_lines_original, start_line_modified, num_lines_modified
    else:
        return None, None


def get_total_commits(repo_path: str) -> int:
    """Get the total number of commits in the specified Git repository."""
    try:
        # Run the git rev-list command to count total commits
        result = subprocess.run(
            ['git', '-C', repo_path, 'rev-list', '--count', 'HEAD'],
            capture_output=True, text=True, check=True
        )
        # Extract the total commit count from the command output
        commit_count = int(result.stdout.strip())
        return commit_count
    except subprocess.CalledProcessError as e:
        print(f"Error running git command: {e}")
        return 0
    except ValueError as e:
        print(f"Error converting commit count to integer: {e}")

        return 0


def get_commits_and_hashes(repo_path, older_version, newer_version):
    # Count the number of commits
    count_command = ['git', '-C', repo_path, 'rev-list', '--count', f'{older_version}..{newer_version}']
    commit_count = subprocess.check_output(count_command).strip().decode('utf-8')

    # Get the commit hashes
    hash_command = ['git', '-C', repo_path, 'rev-list', f'{older_version}..{newer_version}']
    commit_hashes = subprocess.check_output(hash_command).strip().decode('utf-8').split('\n')

    return int(commit_count), commit_hashes


def get_versions(repo_path, fuzzy_version1, fuzzy_version2):
    # Get all tags
    tags = get_all_tags(repo_path)

    # Find the closest matching tags
    closest_tag1 = get_closest_version(tags, fuzzy_version1)
    closest_tag2 = get_closest_version(tags, fuzzy_version2)

    return closest_tag1, closest_tag2


def find_hash_position_in_sorted_list(hashes_list, fix_hash):
    """
    This function sorts a list of tuples (CVE-ID, value) by CVE-ID,
    then finds and returns the position of the given CVE-ID in the sorted list.

    Parameters:
    hashes_list (List[Tuple[str, int]]): A list of tuples where each tuple contains a CVE-ID and an associated value.
    fix_hash (str): The CVE-ID whose position in the sorted list needs to be found.

    Returns:
    int: The position (index) of the CVE-ID in the sorted list, or -1 if not found.
    """

    # Sort the list of tuples by CVE-ID
    sorted_hashes_list = sorted(hashes_list, key=lambda x: x[1], reverse=True)

    # Find the position of the target CVE-ID
    for i, (c_hash, _) in enumerate(sorted_hashes_list):
        if c_hash == fix_hash:
            return i

    # Return -1 if the CVE-ID is not found in the list
    return -1


def extract_modifications(data):
    """
    Extracts modified files and vulnerable functions from the given dictionary.

    :param data: Dictionary containing modification data.
    :return: A tuple containing two lists:
             - modified_files: List of modified file paths.
             - vulnerable_functions: List of vulnerable functions.
    """
    modified_files = []
    vulnerable_functions = []

    # Iterate through the modifications dictionary
    for file_path, file_data in data.get('modifications', {}).items():
        modified_files.append(file_path)  # Add file paths to modified files list

        # Check for vulnerable functions in modifications
        for modification in file_data.get('modifications', []):
            if modification.get('modified_func'):
                vulnerable_functions.append(modification['modified_func'])

    return modified_files, vulnerable_functions


def write_json_line(file_path, record):
    with open(file_path, 'a') as f:
        # json.dumps(record, f, indent=4)
        f.write(json.dumps(record) + '\n')
        # f.write('\n')  # Write each record on a new line


def find_top_k_and_position(hashes_list, fix_hash, k=5):
    """
    This function sorts a list of tuples (hash, value) by value in descending order.
    It returns the top k tuples (hash, value) and the position of the given hash in the sorted list.

    Parameters:
    hashes_list (List[Tuple[str, float]]): A list of tuples where each tuple contains a hash and an associated score.
    fix_hash (str): The hash whose position in the sorted list needs to be found.
    k (int): The number of top entries to return. Default is 5.

    Returns:
    Tuple[List[Tuple[str, float]], int]: A tuple containing:
        - The list of top k tuples (hash, value)
        - The position of the given hash in the sorted list, or -1 if not found.
    """

    # Sort the list of tuples by value in descending order
    sorted_hashes_list = sorted(hashes_list, key=lambda x: x[1], reverse=True)

    # Get the top k tuples (default is top 5)
    top_k = sorted_hashes_list[:k]

    # Find the position of the target hash
    position = -1
    for i, (c_hash, _) in enumerate(sorted_hashes_list):
        if c_hash == fix_hash:
            position = i
            break

    # Return the top k tuples and the position of the fix_hash
    return top_k, position


# ------------------


logging.getLogger("transformers").setLevel(logging.ERROR)

load_dotenv()

openai_api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI()

model_path = (
    "../../deepseek-coder-6.7b-instruct.Q2_K"
    ".gguf")


#
# model = GenerativeModel("gemini-1.5-pro-001")


# def gemini_cosine_similarity(
#         texts: List[str],
#         task: str = "RETRIEVAL_DOCUMENT",
#         model_name: str = "text-embedding-004", #"textembedding-gecko@003",
#         #dimensionality: Optional[int] = None,  # No need to specify dimensionality
#         dimensionality: Optional[int] = 256, # only needed when using "text-embedding-004" embedding model
# ) -> float:
#     """
#     Embeds texts with a pre-trained model and computes the cosine similarity.

#     Parameters:
#     texts (List[str]): List of texts to be embedded
#     task (str): Task for the embedding model
#     model_name (str): Pre-trained model name
#     dimensionality (Optional[int]): Dimensionality of the embeddings

#     Returns:
#     float: Cosine similarity between the embeddings of the first two texts
#     """
#     # Embed the texts
#     model = TextEmbeddingModel.from_pretrained(model_name)
#     inputs = [TextEmbeddingInput(text, task) for text in texts]
#     kwargs = dict(output_dimensionality=dimensionality) if dimensionality else {}
#     embeddings = model.get_embeddings(inputs, **kwargs)
#     embedding_values = [embedding.values for embedding in embeddings]

#     # Convert embeddings to numpy arrays
#     vec1 = np.array(embedding_values[0])
#     vec2 = np.array(embedding_values[1])

#     # Compute cosine similarity
#     dot_product = np.dot(vec1, vec2)
#     magnitude_vec1 = np.linalg.norm(vec1)
#     magnitude_vec2 = np.linalg.norm(vec2)

#     if magnitude_vec1 == 0 or magnitude_vec2 == 0:
#         return 0.0  # Handle zero magnitude vectors

#     cosine_sim = dot_product / (magnitude_vec1 * magnitude_vec2)
#     return cosine_sim, [vec1, vec2]


def embed_text(text):
    """Embeds text using the text-embedding-004 model."""
    try:
        response = aiplatform.Embedding.encode(
            endpoint="projects/{}/locations/{}/endpoints/{}".format(PROJECT_ID, LOCATION, "YOUR_ENDPOINT_ID"),
            # Replace with your endpoint ID
            instances=[{"content": text}],
            parameters={"embedding_dimensions": 768}
        )  # embedding_dimensions may need adjusting based on model

        # Extract the embedding
        embedding = response.embeddings[0].values  # Access the embedding array

        return embedding
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def gemini_cosine_similarity(
        texts: List[str],
        task: str = "RETRIEVAL_DOCUMENT",
        model_name: str = "text-embedding-004",
        dimensionality: Optional[int] = 256,
) -> float:
    try:
        # Embed the texts
        model = TextEmbeddingModel.from_pretrained(model_name)
        inputs = [TextEmbeddingInput(text, task) for text in texts]
        kwargs = dict(output_dimensionality=dimensionality) if dimensionality else {}
        embeddings = model.get_embeddings(inputs, **kwargs)
        embedding_values = [embedding.values for embedding in embeddings]

        # Convert embeddings to numpy arrays
        vec1 = np.array(embedding_values[0])
        vec2 = np.array(embedding_values[1])

        # Compute cosine similarity
        dot_product = np.dot(vec1, vec2)
        magnitude_vec1 = np.linalg.norm(vec1)
        magnitude_vec2 = np.linalg.norm(vec2)

        if magnitude_vec1 == 0 or magnitude_vec2 == 0:
            return 0.0  # Handle zero magnitude vectors

        cosine_sim = dot_product / (magnitude_vec1 * magnitude_vec2)
        return cosine_sim, [vec1, vec2]

    except exceptions.InternalServerError as exc:
        print("InternalServerError: 500 Internal error encountered.")
        raise exceptions.from_grpc_error(exc) from exc
    except Exception as e:
        print(f"An unexpected error occurred: {e}")
        raise


def openai_cosine_similarity(text1, text2, model='text-embedding-ada-002'):
    def get_openai_embeddings(input_text, model):
        max_tokens = 8191
        encoder = tiktoken.encoding_for_model('text-embedding-ada-002')
        tokens = encoder.encode(input_text)
        num_tokens = len(tokens)
        # print(f"Number of tokens: {num_tokens}")
        if len(tokens) > max_tokens:
            tokens = tokens[:max_tokens]
        truncated_text = encoder.decode(tokens)

        try:
            response = client.embeddings.create(input=truncated_text, model=model)
            return response.data[0].embedding
        except:
            return None

    def cosine_similarity(emb1, emb2):
        vec1 = np.array(emb1)
        vec2 = np.array(emb2)
        dot_product = np.dot(vec1, vec2)
        norm_vec1 = np.linalg.norm(vec1)
        norm_vec2 = np.linalg.norm(vec2)
        return dot_product / (norm_vec1 * norm_vec2)

    embedding1 = get_openai_embeddings(text1, model)
    embedding2 = get_openai_embeddings(text2, model)

    if embedding1 is None or embedding2 is None:
        return None
    return cosine_similarity(embedding1, embedding2), [embedding1, embedding2]


def calculate_cosine_similarity(text1, text2):
    tokenizer = BertTokenizer.from_pretrained('bert-base-uncased')
    model = BertModel.from_pretrained('bert-base-uncased')

    # Tokenize and encode the text passages
    tokens1 = tokenizer(text1, return_tensors='pt', truncation=True)
    tokens2 = tokenizer(text2, return_tensors='pt', truncation=True)

    # Get the BERT embeddings
    with torch.no_grad():
        outputs1 = model(**tokens1)
        outputs2 = model(**tokens2)

    # Extract the [CLS] token embeddings as sentence representations
    embeddings1 = outputs1.last_hidden_state[:, 0, :]
    embeddings2 = outputs2.last_hidden_state[:, 0, :]

    # Calculate the cosine similarity
    cosine_similarity = torch.cosine_similarity(embeddings1, embeddings2)

    return cosine_similarity.item()


def consolidate_and_rank_top_k(openai_ranked, gemini_ranked, key="similarity_score", top_k=10):
    # Combine both lists
    combined_ranked = openai_ranked + gemini_ranked

    # Dictionary to store the highest-ranked entry for each c_hash
    unique_commits = {}
    for entry in combined_ranked:
        c_hash = entry["commit_url"].split("/")[-1]
        if c_hash not in unique_commits or entry[key] < unique_commits[c_hash][key]:
            unique_commits[c_hash] = entry

    # Extract the unique values, sort them by similarity score, and pick top_k
    top_ranked = sorted(unique_commits.values(), key=lambda x: x[key], reverse=True)[:top_k]
    return top_ranked


def normalise_scores(ranked_list, score_key="similarity_score"):
    # Extract the range of scores
    scores = [entry[score_key] for entry in ranked_list]
    min_score, max_score = min(scores), max(scores)

    # Normalise the scores to a [0, 1] range
    for entry in ranked_list:
        entry["normalised_score"] = (entry[score_key] - min_score) / (
                max_score - min_score) if max_score > min_score else 0.0
    return ranked_list


def consolidate_normalised_and_rank(openai_ranked, gemini_ranked, top_k=10):
    # Normalise scores for both OpenAI and Gemini
    openai_ranked = normalise_scores(openai_ranked, score_key="similarity_score")
    gemini_ranked = normalise_scores(gemini_ranked, score_key="similarity_score")

    # Combine both lists
    combined_ranked = openai_ranked + gemini_ranked

    # Deduplicate by c_hash, keeping the highest normalised score
    unique_commits = {}
    for entry in combined_ranked:
        c_hash = entry["commit_url"].split("/")[-1]
        if c_hash not in unique_commits or entry["normalised_score"] > unique_commits[c_hash]["normalised_score"]:
            unique_commits[c_hash] = entry

    # Sort first by normalised_score (descending), then by absolute_score (descending)
    top_ranked = sorted(
        unique_commits.values(),
        key=lambda x: (x["normalised_score"], x["similarity_score"]),
        reverse=True
    )[:top_k]
    return top_ranked


# def deep_seek_calculate_code_similarity(source_code1, source_code2, model_path):
#     llm = llama_cpp.Llama(model_path=model_path, embedding=True)

#     def get_embedding(code):
#         """Calculates the average embedding of a code snippet."""
#         embeddings = llm.embed(code.split("\n"))
#         full_embeddings = [np.mean(em, axis=0) for em in embeddings]
#         embeddings_array = np.vstack(full_embeddings)
#         return np.mean(embeddings_array, axis=0)


#     emb1 = get_embedding(source_code1)
#     emb2 = get_embedding(source_code2)

#     a = torch.tensor(emb1)
#     b = torch.tensor(emb2)

#     dot_product = torch.dot(a, b)
#     magnitude_a = torch.norm(a)
#     magnitude_b = torch.norm(b)

#     similarity = dot_product / (magnitude_a * magnitude_b)
#     return similarity.item()


def append_to_file(file_path, text):
    with open(file_path, 'a') as file:
        file.write(text)


def append_emb_csv(file_path, embeddings):
    # Open the CSV file in append mode
    with open(file_path, mode='a', newline='') as file:
        writer = csv.writer(file)

        # Loop through each key and embedding dictionary
        for key, emb_dict in embeddings.items():
            for emb_type, emb_list in emb_dict.items():
                for i, emb in enumerate(emb_list):
                    # Convert numpy array to list if needed
                    if isinstance(emb, np.ndarray):
                        emb = emb.tolist()
                    # Write row to CSV
                    row = [key, f"{emb_type}_{i + 1}"] + emb
                    writer.writerow(row)


def serialize_data(data):
    """Converts sets in the dictionary to lists for JSON serialization."""
    if isinstance(data, dict):
        return {key: serialize_data(value) for key, value in data.items()}
    elif isinstance(data, set):
        return list(data)
    elif isinstance(data, list):
        return [serialize_data(item) for item in data]
    return data


def append_dict_to_file(filename, data_dict):
    """Appends a dictionary as a new line to a text file."""
    serialized_data = serialize_data(data_dict)
    with open(filename, 'a') as file:
        file.write(json.dumps(serialized_data) + '\n')


def log_repo_commits(repo_path, repo=None):
    """
    Logs all commits for the given repository path.

    Parameters:
        repo_path (str): The path to the Git repository.
        repo (str): The previously used repository path (optional).

    Returns:
        list: A list of commit data parsed from the Git log.
    """
    if repo != repo_path:
        repo = repo_path
        content = get_git_log_data(repo_path)  # Assuming this is defined elsewhere
        commits_desc = json.loads(content)
        print("Commits logged........!")
        return commits_desc

    return None


def get_files_n_functions_from_data(data):
    affected_functions = []
    h_headers = 0
    a_lines = 0
    r_lines = 0
    for key, values in data['modifications'].items():
        # print(com[1])
        for modification in values['modifications']:
            hunk_header = modification['hunk_header']
            h_headers += 1
            added_lines = modification['added_lines']
            a_lines += len(added_lines)
            removed_lines = modification['removed_lines']
            r_lines += len(removed_lines)
            try:
                modified_func = modification['modified_func']
            except:
                modified_func = None
            affected_functions.append(modified_func)

    return affected_functions, h_headers, a_lines, r_lines


def get_valid_versions_llm_parsed(repo_path, parsed_result):
    AV = None
    FV = None
    if parsed_result['affected_versions'] and parsed_result['affected_versions'] != 'None' and 'None' not in \
            parsed_result['affected_versions']:
        AV = parsed_result['affected_versions'][-1]

    if parsed_result['fixed_versions'] and parsed_result['fixed_versions'] != 'None' and 'None' not in parsed_result[
        'fixed_versions']:
        if is_valid_git_hash(parsed_result['fixed_versions'][-1]):
            FV = get_latest_tag_from_commit(parsed_result['fixed_versions'][-1], repo_path)
        else:
            FV = parsed_result['fixed_versions'][-1]

    if AV and FV:
        # total_commits, commits_bw_versions = get_commit_range(repo_path, AV, FV)
        total_commits = get_total_commits(repo_path)
        closest_av, closest_fv = get_versions(repo_path, AV, FV)
        if not closest_av and not closest_fv:
            return None, None, None
        print(f"Closest tag to {AV}: {closest_av}")
        print(f"Closest tag to {FV}: {closest_fv}")

        if closest_av == closest_fv:
            closest_av1 = get_previous_version(repo_path, closest_fv)
            closest_av = closest_av1
            print("---")
            print(f"Closest tag for {closest_av}: {closest_av}")
            print(f"Closest tag for {closest_fv}: {closest_fv}")

        return total_commits, closest_av, closest_fv
    else:
        return None, None, None


def get_valid_versions_osv_llm(repo_path, AV, FV):
    total_commits = get_total_commits(repo_path)
    if AV and FV:
        # total_commits, commits_bw_versions = get_commit_range(repo_path, AV, FV)
        closest_av, closest_fv = get_versions(repo_path, AV, FV)
        if not closest_av and not closest_fv:
            return None, None, None
        print(f"Closest tag to {AV}: {closest_av}")
        print(f"Closest tag to {FV}: {closest_fv}")

        if closest_av == closest_fv:
            try:
                closest_fv1 = get_next_version(repo_path, closest_fv)
                closest_fv = closest_fv1
            except IndexError:
                closest_av = get_previous_version(repo_path, closest_fv)
                closest_fv = closest_fv

            print("---")
            print(f"Closest tag for {closest_av}: {closest_av}")
            print(f"Closest tag for {closest_fv}: {closest_fv}")

        return total_commits, closest_av, closest_fv
    else:
        return total_commits, None, None


def get_commit_messages_after_hash(repo_path, commit_hash):
    """
    Get all commit messages after a given commit hash.

    Parameters:
    - repo_path (str): Path to the Git repository.
    - commit_hash (str): The commit hash after which to list commits.

    Returns:
    - List[str]: A list of commit messages.
    """
    try:
        # Construct the Git command
        command = ["git", "-C", repo_path, "log", f"{commit_hash}..HEAD", "--pretty=format:%H %s"]

        # Execute the Git command
        result = subprocess.run(command, capture_output=True, text=True, check=True)

        # Split the result by new lines to get individual commit hashes
        commit_hashes = result.stdout.strip().split("\n")

        return commit_hashes

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while running git command: {e}")
        return []


def get_commit_date(commit_hash):
    try:
        # Run the git show command
        result = subprocess.run(
            ['git', 'show', '--no-patch', '--no-notes', '--pretty=%ci', commit_hash],
            capture_output=True,
            text=True,
            check=True
        )

        # Capture the output
        commit_date = result.stdout.strip()

        return commit_date
    except subprocess.CalledProcessError as e:
        print(f"Error: {e}")
        return None


def get_last_affected(data):
    fix_found = False
    fixed_vers = []
    for range_item in data:
        events = range_item['ranges']
        for event in events:
            for aff in event['events']:
                if 'last_affected' in aff:
                    return fix_found, aff['last_affected']
                if 'fixed' in aff:
                    fix_found = True
                    fixed_vers.append(aff['fixed'])
                    return fix_found, fixed_vers
    return fix_found, None


def get_fixed_version(data):
    if 'fixed' in str(data):
        print(data)


def get_repo(schema):
    repo = None
    for affected in schema['affected']:
        for ran in affected['ranges']:
            if ran['type'] == 'GIT':
                repo = ran['repo']
    return repo


def extract_cve_info(cve_description):
    prompt = f"""
    Extract the following information from the CVE description: 
    1. Only affected versions but valid versions, no other words should be included with version. Affected version must be earlier than the fixed version; they cannot be equal. Return in a list format, if available; otherwise reply 'None'.  If more than one version is returned make them order from lowest version number to the highest version number. Name the list as "affected_versions".

    2. Fixed version but valid versions, no other words should be included with version. Return in a list format, if available; otherwise reply 'None'. If more than one version is returned make them order from lowest version number to the highest version number. Name the list as "fixed_versions".

    3. Impacted files, functions, variables in a list (if available, reply file, function names, or variable names; otherwise reply 'None'). Name the list as "impacted_artifacts". Return as a list containing affected artifacts.

    Please provide the response in the form of a Python dictionary. It should begin with "{{" and end with "}}".
    The dictionary should have the following keys: "affected_versions", "fixed_versions" and "impacted_artifacts". The response should not have any markdown delimiters. Just dictionary string is needed.

    CVE Description: {cve_description}
    Information:
    """
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


def get_txt_file_data(f1, f2):
    with open(f1, 'r') as json_file:
        json_list = list(json_file)
    json_data = []
    for json_str in json_list:
        result = json.loads(json_str)
        json_data.append(result)

    # fix commit not known for the following. Fix version is known however.
    with open(f2, 'r') as f1:
        txt_data = f1.readlines()

    return json_data, txt_data


def info_extraction_from_git_pages(pages_text):
    prompt = f"""
        Extract the following information from the CVE description:
         
        1. Git fix commit hash or fix commit link that fixes the vulnerability, also mention the pull request link that fixes the vulnerability, if it exists. If no such information is available, reply 'None'. Name the key as "fix_commit".

        2. Fixed version after the fix/patches commit is applied, no other words should be included with version. Return in a list format, if available; otherwise reply 'None'. If more than one version is returned, order them from lowest to highest version number. Name the list as "fixed_versions".
        
        3. Confirm whether a fix for the vulnerability exists. Reply with 'Yes' if the fix is mentioned, otherwise reply 'No'. Name the key as "fix_exists".

        4. Briefly describe the vulnerability along with the CVE ID. Also mentioned what causes it. Ensure the CVE ID is included in the description. Name the key as "vulnerability_details".
        
        5. Based on the provided data, extract the vulnerable source files, vulnerable functions by considering the CVE ID. Name the key as "vulnerable artifacts".

        Please provide the response in the form of a Python dictionary. It should begin with "{{" and end with "}}".
        The dictionary should have the following keys: "fix_commit", "fixed_versions", "fix_exists", "vulnerability_details", and "vulnerable artifacts". The response should not have any markdown delimiters. Just dictionary string is needed.

        Git content: {pages_text}
    """

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


def compare_diffs(diff1: defaultdict, diff2: defaultdict) -> bool:
    # Ensure both diffs have the same files being compared
    if set(diff1.keys()) != set(diff2.keys()):
        return False

    # Compare line-by-line content for each file
    for file in diff1:
        # Compare the number of lines
        if len(diff1[file]) != len(diff2[file]):
            return False

        # Compare content line-by-line
        for line1, line2 in zip(diff1[file], diff2[file]):
            if line1 != line2:
                return False

    return True


def get_commit_message_heading(repo_path, commit_hash):
    try:
        commit_msg = subprocess.run(
            ['git', '-C', repo_path, 'show', '-s', '--format=%s', commit_hash],
            capture_output=True,
            text=True
        )
        return commit_msg.stdout.strip()

    except Exception as e:
        return f"Error: {str(e)}"


def findrecord(cve, jsondata):
    for rec in jsondata:
        if cve == rec['cve']:
            return rec
    return None


def download_repo(repo_url, output_dir):
    repo_name = repo_url.split("/")[-1].replace(".git", "")

    repo_path = os.path.join(output_dir, repo_name)
    if not os.path.exists(repo_path):  # download repo to the disk
        subprocess.run(["git", "clone", repo_url, repo_path])
    else:
        print(f"Repository already exists at {repo_path}. Skipping download.")

    return repo_path


def extract_repo_and_author(issue_url):
    match = re.match(r"https://github\.com/([^/]+)/([^/]+)/issues/(\d+)", issue_url)
    if not match:
        raise ValueError("Invalid GitHub issue URL format.")
    author, repo_name, issue_number = match.groups()
    return author, repo_name, int(issue_number)


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


def fetch_content(url, token):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json"  # Use the v3 API for general content retrieval
    }
    try:
        # Send GET request to fetch the page content
        print(f"Fetching content from: {url}")
        response = requests.get(url, headers=headers)

        if response.status_code == 200:
            # Parse the JSON content (since it's GitHub's API response)
            content = response.json()

            # If the page is an issue or PR, you can fetch the relevant data from the JSON
            title = content.get('title', 'No Title')  # Title of the issue or pull request
            body = content.get('body', 'No description')  # Body/description of the issue or PR

            # You can access more fields if needed, such as comments, labels, etc.
            print(f"Title: {title}")
            print(f"Description: {body[:200]}...")  # Preview the first 200 chars of the description

            # Additional information like comments or state
            if 'comments' in content:
                print(f"Comments Count: {content['comments']}")

            print("-" * 40)
            return content  # Return the full content of the page

        else:
            print(f"Failed to retrieve {url}: {response.status_code}")
            return None  # Return None if the page couldn't be retrieved

    except Exception as e:
        print(f"Error fetching {url}: {str(e)}")
        return None  # Return None in case of an error


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


def fetch_github_page_content(url):
    """
    Fetches the content of a GitHub page.

    Args:
        url (str): The URL of the GitHub page to fetch.

    Returns:
        str: The HTML content of the GitHub page if the request is successful.
        None: If the request fails or the page is not found.
    """
    try:
        response = requests.get(url)

        if response.status_code == 200:
            return response.text  # Return the full HTML content of the page
        else:
            print(f"Failed to fetch GitHub Page: {response.status_code}")
            return None
    except requests.exceptions.RequestException as e:
        print(f"Request error for GitHub Page: {e}")
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

        comments_data = comments_response.json()
        comments = [comment['body'] for comment in comments_data]

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
