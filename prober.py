import argparse
import json
import config

# CVE-2025-2588

from library import (
    get_repo, get_osv_schema, get_github_data,
    gemini_generate_vulnerability_response, openai_generate_vulnerability_response,
    extract_cve_data, process_github_references_prober
)


def get_vulnerability_fix_data(cve_id, github_token, ai_model, source):
    """Fetch OSV schema, GitHub references, and extract information."""
    references = None
    git_repo_url = None
    if source == 'osv':
        data = get_osv_schema(cve_id)
        git_repo_url = get_repo(data)
        cve_desc = data.get('details', "No description available")
        references = data.get("references", [])
    elif source == 'nvd':
        cve_desc, references = extract_cve_data(cve_id)

    pages_text, links, analysed_pages, general_references = process_github_references_prober(references, github_token)
    pages_text.append(cve_desc)

    if not pages_text:
        print(f"Error: No issues or pull request URLs found in the references for {cve_id}")
        return {}

    analysed_pages = list(analysed_pages)

    for url in links:
        print("Referenced link:", url)
        issue_title, issue_body, comments, commit_info = get_github_data(url, github_token)
        pages_text.extend([url, issue_title, issue_body, comments, commit_info])

    # extracted_info = info_extraction_from_git_pages(pages_text)

    if ai_model == "gemini":
        ai_response = gemini_generate_vulnerability_response(pages_text)
    elif ai_model == "openai":
        ai_response = openai_generate_vulnerability_response(pages_text)
    else:
        print("Error: Unsupported AI model. Use 'gemini' or 'openai'.")
        return {}

    data = json.loads(ai_response)
    ai_gen_vulnerablity_desc = data.get("vulnerability_details")
    repo = data.get("repo")
    fix_commit = data.get("fix_commit")
    fixed_versions = data.get("fixed_versions")
    fix_exists = data.get("fix_exists")
    vulnerable_artifacts = data.get("vulnerable_artifacts")

    return {
        "cve_id": cve_id,
        "prober-generated-cve-desc": ai_gen_vulnerablity_desc,
        "prober-predicted-repo": repo,
        "osv_cve_desc": cve_desc,
        "osv-git-repo": git_repo_url,
        "analysed_pages": analysed_pages,
        "fix_commits": fix_commit,
        "fixed_versions": fixed_versions,
        "fix_exists": fix_exists,
        "vulnerable_artifacts": vulnerable_artifacts
    }


def main():
    """Main function to handle command-line arguments and process a CVE."""
    parser = argparse.ArgumentParser(description="Fetch CVE details from OSV and analyze related GitHub references.")
    parser.add_argument("--cve", required=True, help="CVE ID (e.g., CVE-2025-23217)")
    parser.add_argument("--source", default="osv", choices=["osv", "nvd"], help="Data source to use (default: osv)")
    parser.add_argument("--ai-model", required=True, choices=["gemini", "openai"],
                        help="AI model to use (gemini or openai)")

    args = parser.parse_args()
    response_data = get_vulnerability_fix_data(args.cve, config.AppConfig.GITHUB_TOKEN, args.ai_model, args.source)

    if response_data:
        print("\n--- Extracted CVE Information ---")
        print(response_data)

    else:
        print("No relevant data found.")


if __name__ == "__main__":
    main()
