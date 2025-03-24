import json
import logging

import numpy as np

from library import get_commit_diff, get_commit_message, get_structured_diffed_data, format_data, curate_data, \
    get_files_n_functions_from_data, openai_cosine_similarity, gemini_cosine_similarity, \
    consolidate_normalised_and_rank, get_cve_desc, process_llm_results, extract_upstream_version, extract_cve_info, \
    extract_and_merge_items, get_valid_versions_osv_llm, get_commits_and_hashes
from . import logger
from .config import AppConfig
#import joblib
from collections import OrderedDict
#from app.services import celery


## celery -A celery_worker.celery worker --loglevel=info
## python3 -m http.server 8000
# CVE-2020-15873
# CVE-2023-26045
# CVE-2022-3959
# CVE-2016-9393
# CVE-2023-5060
# CVE-2020-13112
# CVE-2021-21421

# interesting cases
# CVE-2017-11529


@celery.task(bind=True)
def process_commits(self, g_hashes, repo_path, cve_id, cve_desc, repo_url):
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger(__name__)

    openai_ranked, gemini_ranked, response_data, features_dataset, c = [], [], [], [], 1
    loaded_rf_model = joblib.load('random_forest_model.joblib')
    for c_hash in g_hashes:
        # Get commit diff
        diff_data = get_commit_diff(c_hash, repo_path)

        if len(diff_data) > AppConfig.DIFF_SIZE_THRESHOLD:
            continue  # Skip large diffs
        logger.info(f"Commit diff length: {len(diff_data)}")
        commit_message = ' '.join(get_commit_message(repo_path, c_hash).split("\n"))
        structured_diff_data = get_structured_diffed_data(commit_message, diff_data)
        curated_data = curate_data(c_hash, structured_diff_data, cve_id, repo_path)
        data_instance, test_instance = format_data(c_hash, commit_message, curated_data)
        curated_git_info = str(test_instance)
        affected_files = list(data_instance['modifications'].keys())
        affected_functions, hunk_headers, added_lines, removed_lines = get_files_n_functions_from_data(data_instance)
        affected_functions = list(set(affected_functions))
        # OpenAI and Gemini similarity checks
        openai_similarity_score, openai_embeddings = openai_cosine_similarity(cve_desc, curated_git_info)
        if openai_similarity_score is None:
            continue

        gemini_similarity_score, gemini_embeddings = gemini_cosine_similarity([cve_desc, curated_git_info])

        stop_words = {"is", "are", "has", "not", "when", "the", "a", "an", "if", "this", "of", "in", "to", "and", "can"}
        cve_det = cve_desc.split()
        filtered_cve = [word for word in cve_det if word not in stop_words]
        comm_msg = commit_message.split()
        filtered_comm_msg = [word for word in comm_msg if word not in stop_words]
        common_words = len(set(filtered_cve) & set(filtered_comm_msg))
        print(len(set(filtered_cve) & set(filtered_comm_msg)), (set(filtered_cve) & set(filtered_comm_msg)))

        features = [len(cve_desc.split()), len(str(test_instance).split()), len(commit_message.split()), common_words,
                    len(affected_files), len(affected_functions),
                    hunk_headers, added_lines, removed_lines, openai_similarity_score, gemini_similarity_score]
        features_dataset.append(features)
        features_array = np.array(features)
        test_sample = features_array.reshape(1, -1)
        prediction = loaded_rf_model.predict(test_sample)
        prediction = ''.join(map(str, prediction))

        # Collect results and update progress
        # Construct structured dictionaries for easy parsing in HTML

        openai_ranked.append({
            "source": "OpenAI",
            "commit_url": f"{repo_url}/commit/{c_hash}",
            "similarity_score": openai_similarity_score,
            "affected_files": affected_files,
            "affected_functions": affected_functions,
            "hunk_headers": hunk_headers,
            "added_lines": added_lines,
            "removed_lines": removed_lines,
            "model_prediction": prediction
        })
        gemini_ranked.append({
            "source": "Gemini",
            "commit_url": f"{repo_url}/commit/{c_hash}",
            "similarity_score": gemini_similarity_score,
            "affected_files": affected_files,
            "affected_functions": affected_functions,
            "hunk_headers": hunk_headers,
            "added_lines": added_lines,
            "removed_lines": removed_lines,
            "model_prediction": prediction
        })

        # Update progress every 10 commits
        if c % 2 == 0:
            self.update_state(state='PROGRESS', meta={'current': c, 'total': len(g_hashes)})
        c += 1
    top_k_results = consolidate_normalised_and_rank(openai_ranked, gemini_ranked, top_k=10)

    openai_ranked_sorted = sorted(openai_ranked, key=lambda x: x['similarity_score'], reverse=True)
    gemini_ranked_sorted = sorted(gemini_ranked, key=lambda x: x['similarity_score'], reverse=True)

    # return {"openai_ranked": openai_ranked_sorted, "gemini_ranked": gemini_ranked_sorted, "consolidated_ranks":
    # top_k_results}
    return {"consolidated_ranks": top_k_results}


# Celery task
@celery.task(bind=True)
def automated_fix_miner(self, cve_ids):
    results = []
    output_file = "RESULTS_NO_FIX_AVAIL.json"
    output_dir = "repos"
    openai_ranked, gemini_ranked, response_data, features_dataset, c = [], [], [], [], 1
    loaded_rf_model = joblib.load('random_forest_model.joblib')
    AppConfig.TOP_K
    dictionary_pattern = AppConfig.DICTIONARY_PATTERN
    bugtracked = False

    for cve_id in cve_ids:
        try:
            # if cve_id == "CVE-2021-26034":
            #     bugtracked = True
            # if not bugtracked:
            #     continue

            cve_desc, repo_url, affected = get_cve_desc(cve_id)
            # if not cve_desc or (repo_url and "liferay-portal" in repo_url):
            #     continue

            # Extract data
            parsed_result = process_llm_results(extract_cve_info(cve_desc), dictionary_pattern)
            if parsed_result and parsed_result.get('fixed_versions') and parsed_result['fixed_versions'] != 'None':
                AV, FV = extract_upstream_version(parsed_result['affected_versions'][-1]), \
                    parsed_result['fixed_versions'][-1]
                if AV and FV:
                    key_words, repo_path, git_repo_url, _, _, _, _, _ = extract_and_merge_items(cve_id, output_dir)
                    if not repo_path:
                        continue
                    print(AV, FV, repo_path)
                    total_commits, closest_av, closest_fv = get_valid_versions_osv_llm(repo_path, AV, FV)
                    g_counts, g_hashes = get_commits_and_hashes(repo_path, closest_av, closest_fv)

                    # Rank commits
                    for c_hash in g_hashes:
                        diff_data = get_commit_diff(c_hash, repo_path)
                        if not diff_data:  # Handle the case where diff_data is empty
                            print(f"Skipping commit {c_hash} due to empty diff.")
                            continue
                        if len(diff_data) > AppConfig.DIFF_SIZE_THRESHOLD:
                            continue  # Skip large diffs
                        logger.info(f"Commit diff length: {len(diff_data)}")
                        commit_message = ' '.join(get_commit_message(repo_path, c_hash).split("\n"))
                        structured_diff_data = get_structured_diffed_data(commit_message, diff_data)
                        curated_data = curate_data(c_hash, structured_diff_data, cve_id, repo_path)
                        print(curated_data)
                        data_instance, test_instance = format_data(c_hash, commit_message, curated_data)
                        curated_git_info = str(test_instance)
                        affected_files = list(data_instance['modifications'].keys())
                        affected_functions, hunk_headers, added_lines, removed_lines = get_files_n_functions_from_data(
                            data_instance)
                        affected_functions = list(set(affected_functions))
                        # OpenAI and Gemini similarity checks
                        openai_similarity_score, openai_embeddings = openai_cosine_similarity(cve_desc,
                                                                                              curated_git_info)
                        if openai_similarity_score is None:
                            continue

                        gemini_similarity_score, gemini_embeddings = gemini_cosine_similarity(
                            [cve_desc, curated_git_info])

                        stop_words = {"is", "are", "has", "not", "when", "the", "a", "an", "if", "this", "of", "in",
                                      "to", "and", "can"}
                        cve_det = cve_desc.split()
                        filtered_cve = [word for word in cve_det if word not in stop_words]
                        comm_msg = commit_message.split()
                        filtered_comm_msg = [word for word in comm_msg if word not in stop_words]
                        common_words = len(set(filtered_cve) & set(filtered_comm_msg))
                        print(len(set(filtered_cve) & set(filtered_comm_msg)),
                              (set(filtered_cve) & set(filtered_comm_msg)))

                        features = [len(cve_desc.split()), len(str(test_instance).split()), len(commit_message.split()),
                                    common_words,
                                    len(affected_files), len(affected_functions),
                                    hunk_headers, added_lines, removed_lines, openai_similarity_score,
                                    gemini_similarity_score]
                        features_dataset.append(features)
                        features_array = np.array(features)
                        test_sample = features_array.reshape(1, -1)
                        prediction = loaded_rf_model.predict(test_sample)
                        prediction = ''.join(map(str, prediction))

                        # Collect results and update progress
                        # Construct structured dictionaries for easy parsing in HTML

                        openai_ranked.append({
                            "source": "OpenAI",
                            "commit_url": f"{repo_url}/commit/{c_hash}",
                            "similarity_score": openai_similarity_score,
                            "affected_files": affected_files,
                            "affected_functions": affected_functions,
                            "hunk_headers": hunk_headers,
                            "added_lines": added_lines,
                            "removed_lines": removed_lines,
                            "model_prediction": prediction
                        })
                        gemini_ranked.append({
                            "source": "Gemini",
                            "commit_url": f"{repo_url}/commit/{c_hash}",
                            "similarity_score": gemini_similarity_score,
                            "affected_files": affected_files,
                            "affected_functions": affected_functions,
                            "hunk_headers": hunk_headers,
                            "added_lines": added_lines,
                            "removed_lines": removed_lines,
                            "model_prediction": prediction
                        })

                        # Update progress every 10 commits
                        if c % 2 == 0:
                            self.update_state(state='PROGRESS', meta={'current': c, 'total': len(g_hashes)})
                        c += 1
                    top_k_results = consolidate_normalised_and_rank(openai_ranked, gemini_ranked, AppConfig.TOP_K)

                    openai_ranked_sorted = sorted(openai_ranked, key=lambda x: x['similarity_score'], reverse=True)
                    gemini_ranked_sorted = sorted(gemini_ranked, key=lambda x: x['similarity_score'], reverse=True)

                    # return {"openai_ranked": openai_ranked_sorted, "gemini_ranked": gemini_ranked_sorted,
                    # "consolidated_ranks": top_k_results}
        except Exception as e:
            # Properly raise an exception with type information
            self.update_state(
                state='FAILURE',
                meta={
                    'exc_type': type(e).__name__,
                    'exc_message': str(e),
                }
            )
            # Re-raise the exception to propagate it
            raise Exception(f"{type(e).__name__}: {str(e)}")

        response = OrderedDict([
            ("cve", cve_id),
            ("cve_desc", cve_desc),
            ("github_url", git_repo_url),
            ("total_commits", total_commits),
            ("filtered_commits_bw_vers", g_counts),
            ("affected_version", closest_av),
            ("fixed_version", closest_fv),
            ("llm_parsed", parsed_result),
            # ("tags", get_all_tags(repo_path)),
            ("consolidated_ranks", top_k_results)
        ])

        # Read existing data if the file exists
        try:
            with open(output_file, 'r') as f:
                data = json.load(f)
        except FileNotFoundError:
            data = []  # Start with an empty list if the file doesn't exist

        # Append the new response to the data
        data.append(response)

        # Write the updated data back to the file
        with open(output_file, 'w') as f:
            json.dump(data, f, indent=4)

    print(f"All responses appended to {output_file}")

    return data  # response

# from app import celery, logger
# from library import *
# from .config import AppConfig
# import joblib
# from collections import OrderedDict
#
#
# ## celery -A celery_worker.celery worker --loglevel=info
# ## python3 -m http.server 8000
# # CVE-2020-15873
# # CVE-2023-26045
# # CVE-2022-3959
# # CVE-2016-9393
# # CVE-2023-5060
# # CVE-2020-13112
# # CVE-2021-21421
#
# # interesting cases
# # CVE-2017-11529
#
# @celery.task(bind=True)
# def process_commits(self, g_hashes, repo_path, cve_id, cve_desc, repo_url):
#     openai_ranked, gemini_ranked, response_data, features_dataset, c = [], [], [], [], 1
#     loaded_rf_model = joblib.load('random_forest_model.joblib')
#     for c_hash in g_hashes:
#         # Get commit diff
#         diff_data = get_commit_diff(c_hash, repo_path)
#
#         if len(diff_data) > AppConfig.DIFF_SIZE_THRESHOLD:
#             continue  # Skip large diffs
#         logger.info(f"Commit diff length: {len(diff_data)}")
#         commit_message = ' '.join(get_commit_message(repo_path, c_hash).split("\n"))
#         structured_diff_data = get_structured_diffed_data(commit_message, diff_data)
#         curated_data = curate_data(c_hash, structured_diff_data, cve_id, repo_path)
#         data_instance, test_instance = format_data(c_hash, commit_message, curated_data)
#         curated_git_info = str(test_instance)
#         affected_files = list(data_instance['modifications'].keys())
#         affected_functions, hunk_headers, added_lines, removed_lines = get_files_n_functions_from_data(data_instance)
#         affected_functions = list(set(affected_functions))
#         # OpenAI and Gemini similarity checks
#         openai_similarity_score, openai_embeddings = openai_cosine_similarity(cve_desc, curated_git_info)
#         if openai_similarity_score is None:
#             continue
#
#         gemini_similarity_score, gemini_embeddings = gemini_cosine_similarity([cve_desc, curated_git_info])
#
#         stop_words = {"is", "are", "has", "not", "when", "the", "a", "an", "if", "this", "of", "in", "to", "and", "can"}
#         cve_det = cve_desc.split()
#         filtered_cve = [word for word in cve_det if word not in stop_words]
#         comm_msg = commit_message.split()
#         filtered_comm_msg = [word for word in comm_msg if word not in stop_words]
#         common_words = len(set(filtered_cve) & set(filtered_comm_msg))
#         print(len(set(filtered_cve) & set(filtered_comm_msg)), (set(filtered_cve) & set(filtered_comm_msg)))
#
#         features = [len(cve_desc.split()), len(str(test_instance).split()), len(commit_message.split()), common_words,
#                     len(affected_files), len(affected_functions),
#                     hunk_headers, added_lines, removed_lines, openai_similarity_score, gemini_similarity_score]
#         features_dataset.append(features)
#         features_array = np.array(features)
#         test_sample = features_array.reshape(1, -1)
#         prediction = loaded_rf_model.predict(test_sample)
#         prediction = ''.join(map(str, prediction))
#
#         # Collect results and update progress
#         # Construct structured dictionaries for easy parsing in HTML
#
#         openai_ranked.append({
#             "source": "OpenAI",
#             "commit_url": f"{repo_url}/commit/{c_hash}",
#             "similarity_score": openai_similarity_score,
#             "affected_files": affected_files,
#             "affected_functions": affected_functions,
#             "hunk_headers": hunk_headers,
#             "added_lines": added_lines,
#             "removed_lines": removed_lines,
#             "model_prediction": prediction
#         })
#         gemini_ranked.append({
#             "source": "Gemini",
#             "commit_url": f"{repo_url}/commit/{c_hash}",
#             "similarity_score": gemini_similarity_score,
#             "affected_files": affected_files,
#             "affected_functions": affected_functions,
#             "hunk_headers": hunk_headers,
#             "added_lines": added_lines,
#             "removed_lines": removed_lines,
#             "model_prediction": prediction
#         })
#
#         # Update progress every 10 commits
#         if c % 2 == 0:
#             self.update_state(state='PROGRESS', meta={'current': c, 'total': len(g_hashes)})
#         c += 1
#     top_k_results = consolidate_normalised_and_rank(openai_ranked, gemini_ranked, top_k=10)
#
#     openai_ranked_sorted = sorted(openai_ranked, key=lambda x: x['similarity_score'], reverse=True)
#     gemini_ranked_sorted = sorted(gemini_ranked, key=lambda x: x['similarity_score'], reverse=True)
#
#     # return {"openai_ranked": openai_ranked_sorted, "gemini_ranked": gemini_ranked_sorted, "consolidated_ranks":
#     # top_k_results}
#     return {"consolidated_ranks": top_k_results}
#
#
# # Celery task
# @celery.task(bind=True)
# def automated_fix_miner(self, cve_ids):
#     results = []
#     output_file = "RESULTS_NO_FIX_AVAIL.json"
#     output_dir = "repos"
#     openai_ranked, gemini_ranked, response_data, features_dataset, c = [], [], [], [], 1
#     loaded_rf_model = joblib.load('random_forest_model.joblib')
#     AppConfig.TOP_K
#     dictionary_pattern = AppConfig.DICTIONARY_PATTERN
#     bugtracked = False
#
#     for cve_id, fix in cve_ids:
#         try:
#             # if cve_id == "CVE-2021-26034":
#             #     bugtracked = True
#             # if not bugtracked:
#             #     continue
#
#             cve_desc, repo_url, affected = get_cve_desc(cve_id)
#             # if not cve_desc or (repo_url and "liferay-portal" in repo_url):
#             #     continue
#
#             # Extract data
#             parsed_result = process_llm_results(extract_cve_info(cve_desc), dictionary_pattern)
#             if parsed_result and parsed_result.get('fixed_versions') and parsed_result['fixed_versions'] != 'None':
#                 AV, FV = extract_upstream_version(parsed_result['affected_versions'][-1]), \
#                     parsed_result['fixed_versions'][-1]
#                 if AV and FV:
#                     key_words, repo_path, git_repo_url, _, _, _, _, _ = extract_and_merge_items(cve_id, output_dir)
#                     if not repo_path:
#                         continue
#                     print(AV, FV, repo_path)
#                     total_commits, closest_av, closest_fv = get_valid_versions_osv_llm(repo_path, AV, FV)
#                     g_counts, g_hashes = get_commits_and_hashes(repo_path, closest_av, closest_fv)
#
#                     # Rank commits
#                     for c_hash in g_hashes:
#                         diff_data = get_commit_diff(c_hash, repo_path)
#                         if len(diff_data) > AppConfig.DIFF_SIZE_THRESHOLD:
#                             continue  # Skip large diffs
#                         logger.info(f"Commit diff length: {len(diff_data)}")
#                         commit_message = ' '.join(get_commit_message(repo_path, c_hash).split("\n"))
#                         structured_diff_data = get_structured_diffed_data(commit_message, diff_data)
#                         curated_data = curate_data(c_hash, structured_diff_data, cve_id, repo_path)
#                         data_instance, test_instance = format_data(c_hash, commit_message, curated_data)
#                         curated_git_info = str(test_instance)
#                         affected_files = list(data_instance['modifications'].keys())
#                         affected_functions, hunk_headers, added_lines, removed_lines = get_files_n_functions_from_data(
#                             data_instance)
#                         affected_functions = list(set(affected_functions))
#                         # OpenAI and Gemini similarity checks
#                         openai_similarity_score, openai_embeddings = openai_cosine_similarity(cve_desc,
#                                                                                               curated_git_info)
#                         if openai_similarity_score is None:
#                             continue
#
#                         gemini_similarity_score, gemini_embeddings = gemini_cosine_similarity(
#                             [cve_desc, curated_git_info])
#
#                         stop_words = {"is", "are", "has", "not", "when", "the", "a", "an", "if", "this", "of", "in",
#                                       "to", "and", "can"}
#                         cve_det = cve_desc.split()
#                         filtered_cve = [word for word in cve_det if word not in stop_words]
#                         comm_msg = commit_message.split()
#                         filtered_comm_msg = [word for word in comm_msg if word not in stop_words]
#                         common_words = len(set(filtered_cve) & set(filtered_comm_msg))
#                         print(len(set(filtered_cve) & set(filtered_comm_msg)),
#                               (set(filtered_cve) & set(filtered_comm_msg)))
#
#                         features = [len(cve_desc.split()), len(str(test_instance).split()), len(commit_message.split()),
#                                     common_words,
#                                     len(affected_files), len(affected_functions),
#                                     hunk_headers, added_lines, removed_lines, openai_similarity_score,
#                                     gemini_similarity_score]
#                         features_dataset.append(features)
#                         features_array = np.array(features)
#                         test_sample = features_array.reshape(1, -1)
#                         prediction = loaded_rf_model.predict(test_sample)
#                         prediction = ''.join(map(str, prediction))
#
#                         # Collect results and update progress
#                         # Construct structured dictionaries for easy parsing in HTML
#
#                         openai_ranked.append({
#                             "source": "OpenAI",
#                             "commit_url": f"{repo_url}/commit/{c_hash}",
#                             "similarity_score": openai_similarity_score,
#                             "affected_files": affected_files,
#                             "affected_functions": affected_functions,
#                             "hunk_headers": hunk_headers,
#                             "added_lines": added_lines,
#                             "removed_lines": removed_lines,
#                             "model_prediction": prediction
#                         })
#                         gemini_ranked.append({
#                             "source": "Gemini",
#                             "commit_url": f"{repo_url}/commit/{c_hash}",
#                             "similarity_score": gemini_similarity_score,
#                             "affected_files": affected_files,
#                             "affected_functions": affected_functions,
#                             "hunk_headers": hunk_headers,
#                             "added_lines": added_lines,
#                             "removed_lines": removed_lines,
#                             "model_prediction": prediction
#                         })
#
#                         # Update progress every 10 commits
#                         if c % 2 == 0:
#                             self.update_state(state='PROGRESS', meta={'current': c, 'total': len(g_hashes)})
#                         c += 1
#                     top_k_results = consolidate_normalised_and_rank(openai_ranked, gemini_ranked, AppConfig.TOP_K)
#
#                     openai_ranked_sorted = sorted(openai_ranked, key=lambda x: x['similarity_score'], reverse=True)
#                     gemini_ranked_sorted = sorted(gemini_ranked, key=lambda x: x['similarity_score'], reverse=True)
#
#                     # return {"openai_ranked": openai_ranked_sorted, "gemini_ranked": gemini_ranked_sorted,
#                     # "consolidated_ranks": top_k_results}
#         except Exception as e:
#             # Log and handle errors
#             self.update_state(state='FAILURE', meta={'error': str(e)})
#             raise e
#
#         response = OrderedDict([
#             ("cve", cve_id),
#             ("cve_desc", cve_desc),
#             ("github_url", git_repo_url),
#             ("total_commits", total_commits),
#             ("filtered_commits_bw_vers", g_counts),
#             ("affected_version", closest_av),
#             ("fixed_version", closest_fv),
#             ("llm_parsed", parsed_result),
#             ("tags", get_all_tags(repo_path)),
#             ("consolidated_ranks", top_k_results)
#         ])
#
#         # Read existing data if the file exists
#         try:
#             with open(output_file, 'r') as f:
#                 data = json.load(f)
#         except FileNotFoundError:
#             data = []  # Start with an empty list if the file doesn't exist
#
#         # Append the new response to the data
#         data.append(response)
#
#         # Write the updated data back to the file
#         with open(output_file, 'w') as f:
#             json.dump(data, f, indent=4)
#
#     print(f"All responses appended to {output_file}")
#
#     return response
