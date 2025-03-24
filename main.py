from library import get_repo, get_osv_schema, process_github_references, get_github_data, \
    info_extraction_from_git_pages, gemini_generate_vulnerability_response

GITHUB_TOKEN = "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"

cve_id = "CVE-2025-23217"

data = get_osv_schema(cve_id)

git_repo_url = get_repo(data)

cve_desc = data.get('details', "No description available")

pages_text, links, analysed_pages, general_references = process_github_references(data, GITHUB_TOKEN)

pages_text.extend([cve_desc])

if not pages_text:
    print(f"error: No issues or pull request URLs found in the references for {cve_id}")

analysed_pages = list(analysed_pages)

for url in links:
    print("referenced links", url)
    issue_title, issue_body, comments, commit_info = get_github_data(url, GITHUB_TOKEN)
    pages_text.extend([url, issue_title, issue_body, comments, commit_info])

extracted_info = info_extraction_from_git_pages(pages_text)
gemini_extracted_info = gemini_generate_vulnerability_response(pages_text)
# print(extracted_info)

# ---------------
# llm_res = extract_cve_info(cve_desc)
# parsed_result = process_llm_results(llm_res, AppConfig.DICTIONARY_PATTERN)
# if parsed_result is None:
#     return {"error": "Parsing failed"}, 500

# if git_repo_url:
#     repo_path = download_repo(git_repo_url, AppConfig.OUTPUT_DIR)
#
# total_commits = get_total_commits(repo_path)
# ver_tags = get_all_tags(repo_path)
#
# from .services import redis_client
# self.store_in_redis(redis_client, cve_id, {
#     "repo_path": repo_path,
#     "total_commits": total_commits,
#     "cve_desc": cve_desc,
#     "repo_url": git_repo_url,
#     "ver_tags": ver_tags
# })

response_data = {
    "cve_id": cve_id,
    "cve_desc": cve_desc,
    "git_repo_url": git_repo_url,
    "analysed_pages": analysed_pages,
    # "repo_path": repo_path,
    # "total_commits": total_commits,
    # "ver_tags": ver_tags,
    "fix_commits": extracted_info
}
print(response_data)
print(gemini_extracted_info)