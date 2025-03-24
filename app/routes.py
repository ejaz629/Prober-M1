from flask import request, make_response, jsonify
from collections import OrderedDict
from library import *
from .config import AppConfig
from flask_restx import Namespace, Resource

# Define the main namespace for general routes
ns = Namespace('APIs', description="Vulnerability management APIs", doc=False)

GITHUB_TOKEN = AppConfig.github_token


# curl -X POST http://localhost:5000/process_cves -H "Content-Type: application/json" -d '{"cve_ids": [[
# "CVE-2021-21421", "fix_hash1"], ["CVE-2021-21421", "fix_hash2"]]}'

# @app.route('/set_user_options', methods=['POST'])
# def set_user_options():
#     app.config['USER_OPTIONS'] = {'option1': 'value1', 'option2': 'value2'}
#     return jsonify({"message": "User options updated!"})
#
#
# @ns.route('/send')
# class SendEvent(Resource):
#     def get(self):
#         # Push data to the SSE stream
#         sse.publish({"message": "Hello, this is an SSE message!"}, type='message')
#         return "Event sent!"


# @ns.route('/get_user_options', methods=['GET'])
# class GetUserOptions(Resource):
#     def get(self):
#         return jsonify(app.config['USER_OPTIONS'])


# @ns.route('/publish')
# class PublishMessage(Resource):
#     def post(self):
#         """
#         Publish a real-time update message.
#         """
#         sse.publish({"message": "This is a real-time update!"}, type="update", channel="updates")
#         return {"message": "Message sent!"}, 200


@ns.route('/terminate_task/<task_id>', methods=['POST'])
class TerminateTask(Resource):
    def post(self, task_id):
        """
        Terminate a Celery task by its ID.
        """
        from .services import celery
        celery.control.revoke(task_id, terminate=True)
        return jsonify({"status": "Task terminated"}), 200


# # Define models for request and response
# commit_count_request_model = ns.model('CommitCountRequest', {
#     'cve_id': {'type': 'string', 'required': True, 'description': 'CVE ID for analysis'}
# })
#
# commit_count_response_model = ns.model('CommitCountResponse', {
#     'cve_id': {'type': 'string', 'description': 'CVE ID for analysis'},
#     'commits_between_versions': {'type': 'integer', 'description': 'Count of commits between tags'},
#     'g_hashes': {'type': 'array', 'items': {'type': 'string'}, 'description': 'List of commit hashes'}
# })
#
# # Define models for request and response using Flask-RESTx fields
# commit_count_request_model = ns.model('CommitCountRequest', {
#     'cve_id': fields.String(required=True, description='CVE ID for analysis')
# })
#
# commit_count_response_model = ns.model('CommitCountResponse', {
#     'cve_id': fields.String(description='CVE ID for analysis'),
#     'commits_between_versions': fields.Integer(description='Count of commits between tags'),
#     'g_hashes': fields.List(fields.String, description='List of commit hashes')
# })


@ns.route('/get_commit_count')
class GetCommitCount(Resource):
    """
    API endpoint to get the commit count between two Git tags.
    """

    @ns.doc(
        description="Calculate the commit count between two tags for a given CVE.",
        params={
            'affected_tag': 'The affected version tag',
            'fixed_tag': 'The fixed version tag'
        }
    )
    # @ns.expect(commit_count_request_model)
    # @ns.response(200, 'Success', commit_count_response_model)
    @ns.response(400, 'Bad Request')
    @ns.response(404, 'Not Found')
    @ns.response(500, 'Internal Server Error')
    def post(self):
        """
        Calculate the commit count between the affected and fixed tags for a given CVE.
        """
        affected_tag = request.args.get('affected_tag')
        fixed_tag = request.args.get('fixed_tag')
        data = request.get_json()

        cve_id = data.get('cve_id')
        if not cve_id:
            return jsonify({"error": "CVE ID is required"}), 400

        try:
            from .services import redis_client
            repo_path_json = redis_client.get(f"repo_path:{cve_id}")
            if not repo_path_json:
                return jsonify({"error": "Repository path not found for given CVE ID"}), 404

            repo_path = json.loads(repo_path_json)
            print(repo_path, affected_tag, cve_id)

            # Implement your logic to calculate the commit count between tags
            g_counts, g_hashes = get_commits_and_hashes(repo_path, affected_tag, fixed_tag)
            print(g_counts)

            redis_client.set(f"g_counts:{cve_id}", json.dumps(g_counts))
            redis_client.set(f"g_hashes:{cve_id}", json.dumps(g_hashes))

            response = OrderedDict([
                ("cve_id", cve_id),
                ("commits_between_versions", g_counts),
                ("g_hashes", g_hashes)
            ])

            return make_response(jsonify(response), 200)
        except Exception as e:
            return make_response(jsonify({"error": str(e)}), 500)


# API Route: Extract Fix Commits
@ns.route("/cve_fix_extractor")
class FixCommitExtraction(Resource):
    @ns.doc(
        description="Extracts fix commits from GitHub issues and PRs related to the given CVE ID.",
        params={"cve_id": "CVE Identifier (e.g., CVE-2023-12345)"}
    )
    def get(self):
        """Extract fix commits from GitHub issues and PRs."""
        cve_id = request.args.get('cve_id')

        if not cve_id:
            return {"error": "Missing CVE ID"}, 400

        data = get_osv_schema(cve_id)

        if not data:
            return {"error": f"No OSV schema found for {cve_id}"}, 404

        cve_desc = data.get('details', "No description available")
        git_repo_url = get_repo(data)

        pages_text, links, analysed_pages, general_references = process_github_references(data, GITHUB_TOKEN)

        pages_text.extend([cve_desc])

        if not pages_text:
            return {"error": f"No issues or pull request URLs found in the references for {cve_id}"}, 404

        analysed_pages = list(analysed_pages)

        for url in links:
            print("referenced links", url)
            issue_title, issue_body, comments, commit_info = get_github_data(url, GITHUB_TOKEN)
            pages_text.extend([url, issue_title, issue_body, comments, commit_info])

        extracted_info = info_extraction_from_git_pages(pages_text)
        # extracted_info = gemini_generate_vulnerability_response(pages_text)
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

        return response_data, 200

    @staticmethod
    def store_in_redis(redis_client, cve_id, data):
        """
        Store CVE-related data in Redis.
        """
        try:
            for key, value in data.items():
                redis_client.set(f"{key}:{cve_id}", json.dumps(value))
        except Exception as e:
            raise Exception(f"Failed to store data in Redis: {e}")

    # def get(self):
    #     """Extract fix commits from GitHub issues and PRs."""
    #     cve_id = request.args.get('cve_id')
    #
    #     if not cve_id:
    #         return {"error": "Missing CVE ID"}, 400
    #
    #     data = get_osv_schema(cve_id)
    #     cve_desc = data['details']
    #     git_repo_url = get_repo(data)
    #
    #     if not data:
    #         return {"error": f"No OSV schema found for {cve_id}"}, 404
    #
    #     # links = []
    #     # pages_text = []
    #     # analysed_pages = set()
    #     #
    #     # nvd_desc, nvd_references = extract_cve_data(cve_id)  # motivation CVE-2016-5301, because only few referenes in osv, but nvd has several
    #     #
    #     # for reference in data.get("references", []):
    #     # #for url in nvd_references:
    #     #     url = reference.get("url", "")
    #     #     if re.match(r"https://github\.com/.+?/issues/\d+", url):
    #     #         author, repo_name, issue_number = extract_repo_and_author(url)
    #     #         if not author:
    #     #             continue
    #     #
    #     #         issue_title, issue_body, comments, commit_info = get_github_data(url, GITHUB_TOKEN)
    #     #         referenced_urls = get_events_from_issue(GITHUB_TOKEN, author, repo_name, issue_number)
    #     #         pages_text.extend([issue_title, issue_body, comments, commit_info])
    #     #         analysed_pages.add(url)
    #     #         links.extend(referenced_urls)
    #     #         analysed_pages.update(referenced_urls)
    #     #
    #     #     elif re.match(r"https://github\.com/.+?/pull/\d+", url):
    #     #         #url = re.sub(r"(https://github\.com/.+?/pull/\d+).*", r"\1", url)
    #     #         headers = {"Accept": "application/vnd.github.v3+json"}
    #     #
    #     #         try:
    #     #             pr_response = requests.get(url, headers=headers)
    #     #             if pr_response.status_code != 200:
    #     #                 print(f"Failed to fetch PR: {pr_response.status_code}, {pr_response.text}")
    #     #                 continue
    #     #             pr_data = pr_response.json()
    #     #             analysed_pages.extend(url)
    #     #             merge_commit_sha = pr_data.get("merge_commit_sha")
    #     #
    #     #             if merge_commit_sha:
    #     #                 print(f"Merge Commit SHA: {merge_commit_sha}")
    #     #             else:
    #     #                 print("No merge commit found for this PR")
    #     #
    #     #         except requests.exceptions.RequestException as e:
    #     #             print(f"GitHub API request error: {e}")
    #     #             continue
    #
    #     pages_text, links, analysed_pages = process_github_references(data, GITHUB_TOKEN)
    #     print(pages_text, links, analysed_pages)
    #
    #     analysed_pages = list(analysed_pages)
    #     if pages_text:
    #         for url in links:
    #             issue_title, issue_body, comments, commit_info = get_github_data(url, GITHUB_TOKEN)
    #             pages_text.extend([url, issue_title, issue_body, comments, commit_info])
    #
    #         extracted_info = info_extraction_from_git_pages(pages_text)
    #         response_data = {
    #             "cve_id": cve_id,
    #             "cve_desc": cve_desc,
    #             "git_repo_url": git_repo_url,
    #             "analysed_pages": analysed_pages,
    #             "fix_commits": extracted_info
    #         }
    #         return response_data, 200
    #
    #     return {"info": f"No issues or pull request url found in the references for {cve_id}"}, 404


@ns.route('/process_cve')
class ProcessCVE(Resource):
    @ns.doc('process_cve', description='Process a CVE to extract relevant details.')
    @ns.doc(
        'process_cve',
        description='Process a CVE to extract relevant details.',
        params={
            'cve_id': 'The CVE ID to process (e.g., CVE-2021-21421)'
        }
    )
    # @ns.expect(process_cve_model, validate=True)
    # @ns.response(200, 'Success', response_model)
    @ns.response(400, 'Missing required data')
    @ns.response(404, 'Not Found')
    @ns.response(500, 'Server Error')
    def get(self):
        """
        Process a CVE to fetch details, analyse repository, and calculate commits.
        """
        # data = ns.payload
        # cve_id = self.get_cve_id(data)
        cve_id = request.args.get('cve_id')
        if not cve_id:
            return {"error": "CVE ID is required"}, 400

        try:
            response = self.process_cve_logic(cve_id)
            print("here", response)
            return response, 200
        except Exception as e:
            return {"error": str(e)}, 500

    @staticmethod
    def get_cve_id(data):
        """
        Extract the CVE ID from payload or query parameters.
        """
        cve_id = data.get("cve_id") if data else None
        if not cve_id:
            cve_id = request.args.get("cve_id")
        return cve_id

    def process_cve_logic(self, cve_id):
        """
        Core logic to process the CVE, shared between POST and GET methods.
        """

        # Step 1: Fetch CVE description
        cve_desc, repo_url, affected = get_cve_desc(cve_id)
        if not cve_desc:
            # return {"error": "CVE description not found"}, 404
            return {"error": f"{affected}"}, 400

        # Step 2: Process CVE data with LLM
        llm_res = extract_cve_info(cve_desc)
        parsed_result = process_llm_results(llm_res, AppConfig.DICTIONARY_PATTERN)
        if parsed_result is None:
            return {"error": "Parsing failed"}, 500

        # Extract versions
        FV = parsed_result.get("fixed_versions", [None])[-1]
        AV = extract_upstream_version(parsed_result.get("affected_versions", [None])[-1])
        # if not AV:
        #     return {"error": "Missing affected version in CVE description."}, 400
        # if not FV:
        #     return {"error": "Missing fixed version in CVE description."}, 400

        # Step 3: Repository and commit analysis
        key_words, repo_path, *_ = extract_and_merge_items(cve_id, AppConfig.OUTPUT_DIR)
        if not repo_path:
            return {"error": "Repository (type git) not found in the OSV schema."}, 404

        total_commits, closest_av, closest_fv = get_valid_versions_osv_llm(repo_path, AV, FV)
        ver_tags = get_all_tags(repo_path)

        from .services import redis_client
        # Step 4: Calculate commits and save to Redis
        if not closest_av or not closest_fv:
            g_hashes = None
            g_counts = None
        else:
            g_counts, g_hashes = get_commits_and_hashes(repo_path, closest_av, closest_fv)
        self.store_in_redis(redis_client, cve_id, {
            "g_hashes": g_hashes,
            "repo_path": repo_path,
            "cve_desc": cve_desc,
            "repo_url": repo_url,
            "ver_tags": ver_tags
        })

        return OrderedDict([
            ("cve_id", cve_desc),
            ("parsed_result", parsed_result),
            ("repo_path", repo_path),
            ("total_commits", total_commits),
            ("closest_av", closest_av),
            ("closest_fv", closest_fv),
            ("commits_between_versions", g_counts),
            ("repo_url", repo_url),
            ("ver_tags", ver_tags)
        ])

    @staticmethod
    def store_in_redis(redis_client, cve_id, data):
        """
        Store CVE-related data in Redis.
        """
        try:
            for key, value in data.items():
                redis_client.set(f"{key}:{cve_id}", json.dumps(value))
        except Exception as e:
            raise Exception(f"Failed to store data in Redis: {e}")


# @ns.route('/start_task', methods=['POST'])
# class StartClass:
#     from .tasks import process_commits
#     cve_id = request.json['cve_id']
#     g_hashes_json = redis_client.get(f"g_hashes:{cve_id}")
#     if not g_hashes_json:
#         return jsonify({"error": "g_hashes not found for the provided CVE ID"}), 404
#     g_hashes = json.loads(g_hashes_json)
#     repo_path_json = redis_client.get(f"repo_path:{cve_id}")
#     repo_path = json.loads(repo_path_json)
#     cve_desc_json = redis_client.get(f"cve_desc:{cve_id}")
#     cve_desc = json.loads(cve_desc_json)
#     repo_url_json = redis_client.get(f"repo_url:{cve_id}")
#     repo_url = json.loads(repo_url_json)
#
#     task = process_commits.apply_async(args=[g_hashes, repo_path, cve_id, cve_desc, repo_url])
#     return jsonify({'task_id': task.id}), 202

@ns.route('/start_task', methods=['POST'])
class StartTask(Resource):
    def post(self):
        from .services import redis_client
        try:
            # Extract CVE ID from the request
            cve_id = request.json.get('cve_id')
            if not cve_id:
                return jsonify({"error": "CVE ID is required"}), 400

            # Get Redis data for g_hashes, repo_path, cve_desc, and repo_url
            g_hashes_json = redis_client.get(f"g_hashes:{cve_id}")
            if not g_hashes_json:
                return jsonify({"error": "g_hashes not found for the provided CVE ID"}), 404
            g_hashes = json.loads(g_hashes_json)

            repo_path_json = redis_client.get(f"repo_path:{cve_id}")
            if not repo_path_json:
                return jsonify({"error": "repo_path not found for the provided CVE ID"}), 404
            repo_path = json.loads(repo_path_json)

            cve_desc_json = redis_client.get(f"cve_desc:{cve_id}")
            if not cve_desc_json:
                return jsonify({"error": "cve_desc not found for the provided CVE ID"}), 404
            cve_desc = json.loads(cve_desc_json)

            repo_url_json = redis_client.get(f"repo_url:{cve_id}")
            if not repo_url_json:
                return jsonify({"error": "repo_url not found for the provided CVE ID"}), 404
            repo_url = json.loads(repo_url_json)

            # Start the task
            from app.tasks import process_commits
            task = process_commits.apply_async(args=[g_hashes, repo_path, cve_id, cve_desc, repo_url])
            # return jsonify({'task_id': task.id}), 202
            return make_response(jsonify({'task_id': task.id}), 200)
        except Exception as e:
            return jsonify({"error": str(e)}), 500


@ns.route('/task_status/<task_id>')
class TaskStatusResource(Resource):
    def get(self, task_id):
        from .tasks import process_commits
        task = process_commits.AsyncResult(task_id)
        if task.state == 'PROGRESS':
            response = {
                'state': task.state,
                'current': task.info.get('current', 0),
                'total': task.info.get('total', 1)
            }
        elif task.state != 'SUCCESS':
            response = {'state': task.state}
        else:
            response = {'state': task.state, 'result': task.result}

        if 'state' not in response:
            response = {'error': 'Unknown task state', 'task_id': task_id}

        return jsonify(response)


# Define input and output models
# automate_cve_model = ns.model('CVEListModel', {
#     'cve_ids': fields.List(
#         fields.String,
#         description="List of CVE IDs to process",
#         required=True
#     )
# })


@ns.route('/automate')
class SubmitCveTask(Resource):
    @ns.doc('submit_cve_task', description='Submit CVE IDs for processing and track the task.')
    # @ns.expect(automate_cve_model)
    def post(self):
        """
        Submit a list of CVE IDs for processing and return the task ID for tracking.
        """
        from app.services import celery
        from .tasks import automated_fix_miner

        data = request.get_json()  # Parse JSON data from the request
        cve_ids = data.get("cve_ids", [])

        if not cve_ids:
            # Return a plain dictionary to jsonify
            return {"error": "No CVE IDs provided"}, 400

        # Submit the Celery task with the list of CVE IDs
        task = automated_fix_miner.apply_async(args=[cve_ids])

        # Return a JSON-serializable response
        return {"task_id": task.id}, 202

# import threading
#
# from flask import request, jsonify, Response, current_app as app, render_template
# from flask_sse import sse
# import time
# from app import redis_client, socketio, celery
# from collections import OrderedDict
# import json
# from .tasks import process_commits
# from .tasks import automated_fix_miner
# from library import *
# from .config import AppConfig
#
#
# @app.route('/set_user_options', methods=['POST'])
# def set_user_options():
#     app.config['USER_OPTIONS'] = {'option1': 'value1', 'option2': 'value2'}
#     return jsonify({"message": "User options updated!"})
#
#
# @app.route('/send')
# def send_event():
#     # Push data to the SSE stream
#     sse.publish({"message": "Hello, this is an SSE message!"}, type='message')
#     return "Event sent!"
#
#
# @app.route('/get_user_options', methods=['GET'])
# def get_user_options():
#     return jsonify(app.config['USER_OPTIONS'])
#
#
# @app.route('/publish')
# def publish_message():
#     sse.publish({"message": "This is a real-time update!"}, type="update", channel="updates")
#     return "Message sent!"
#
#
# @app.route('/terminate_task/<task_id>', methods=['POST'])
# def terminate_task(task_id):
#     celery.control.revoke(task_id, terminate=True)
#     return jsonify({"status": "Task terminated"}), 200
#
#
# @app.route('/get_commit_count', methods=['POST'])
# def get_commit_count():
#     affected_tag = request.args.get('affected_tag')
#     fixed_tag = request.args.get('fixed_tag')
#     data = request.get_json()
#     cve_id = data.get('cve_id')
#     repo_path_json = redis_client.get(f"repo_path:{cve_id}")
#     repo_path = json.loads(repo_path_json)
#     print(repo_path, affected_tag, cve_id )
#     # Implement your logic to calculate the commit count between tags
#     try:
#         g_counts, g_hashes = get_commits_and_hashes(repo_path, affected_tag, fixed_tag)
#         print(g_counts)
#         redis_client.set(f"g_counts:{cve_id}", json.dumps(g_counts))
#         redis_client.set(f"g_hashes:{cve_id}", json.dumps(g_hashes))
#         response = OrderedDict([
#             ("cve_id", cve_id),
#             ("commits_between_versions", g_counts),
#             ("g_hashes", g_hashes)
#         ])
#         return jsonify(response), 200
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#
#
# @app.route('/process_cve', methods=['POST', 'GET'])
# def process_cve():
#     if request.method == 'POST':
#         data = request.json
#     elif request.method == 'GET':
#         data = {'cve_id': request.args.get('cve_id')}
#     cve_id = data.get("cve_id")
#
#     try:
#         # Step 1: Fetch CVE description
#         cve_desc, repo_url, affected = get_cve_desc(cve_id)
#         if not cve_desc:
#             return jsonify({"error": "CVE description not found"}), 404
#         sse.publish({"progress": 20, "message": "Fetched CVE description"}, type="progress")
#
#         # Step 2: Process CVE data with LLM
#         llm_res = extract_cve_info(cve_desc, data.get("openai_api_key"))
#         parsed_result = process_llm_results(llm_res, AppConfig.DICTIONARY_PATTERN)
#         if parsed_result is None:
#             return jsonify({"error": "Parsing failed"}), 500
#         sse.publish({"progress": 40, "message": "Processed CVE with LLM"}, type="progress")
#
#         # Extract versions
#         FV = parsed_result.get("fixed_versions")[-1] if parsed_result.get("fixed_versions") else None
#         AV = extract_upstream_version(parsed_result['affected_versions'][-1]) if parsed_result.get(
#             "affected_versions") else None
#         if not AV:
#             return jsonify({"error": "Missing affected version"}), 400
#         sse.publish({"progress": 60, "message": "Extracted AV and FV"}, type="progress")
#
#         if not FV:
#             return jsonify({"error": "Missing fixed version"}), 400
#
#         # Step 3: Repository and commit analysis
#         key_words, repo_path, *_ = extract_and_merge_items(cve_id, AppConfig.OUTPUT_DIR)
#         if not repo_path:
#             return jsonify({"error": "Repository not found"}), 404
#         total_commits, closest_av, closest_fv = get_valid_versions_osv_llm(repo_path, AV, FV)
#         sse.publish({"progress": 80, "message": "Completed repository analysis"}, type="progress")
#
#         ver_tags = get_all_tags(repo_path)
#
#         # Step 4: Calculate commits and save to Redis
#         g_counts, g_hashes = get_commits_and_hashes(repo_path, closest_av, closest_fv)
#
#         # Store g_hashes in Redis with cve_id as the key
#         redis_client.set(f"g_hashes:{cve_id}", json.dumps(g_hashes))
#         redis_client.set(f"repo_path:{cve_id}", json.dumps(repo_path))
#         redis_client.set(f"cve_desc:{cve_id}", json.dumps(cve_desc))
#         redis_client.set(f"repo_url:{cve_id}", json.dumps(repo_url))
#         redis_client.set(f"ver_tags:{cve_id}", json.dumps(ver_tags))
#
#         response = OrderedDict([
#             ("cve_id", cve_desc),
#             ("parsed_result", parsed_result),
#             ("repo_path", repo_path),
#             ("total_commits", total_commits),
#             ("closest_av", closest_av),
#             ("closest_fv", closest_fv),
#             ("commits_between_versions", g_counts),
#             ("repo_url", repo_url),
#             ("ver_tags", ver_tags)
#         ])
#         sse.publish({"progress": 100, "message": "Process complete"}, type="progress")
#
#         return jsonify(response), 200
#
#     except Exception as e:
#         return jsonify({"error": str(e)}), 500
#
#
# @app.route('/start_task', methods=['POST'])
# def start_task():
#     cve_id = request.json['cve_id']
#     g_hashes_json = redis_client.get(f"g_hashes:{cve_id}")
#     if not g_hashes_json:
#         return jsonify({"error": "g_hashes not found for the provided CVE ID"}), 404
#     g_hashes = json.loads(g_hashes_json)
#     repo_path_json = redis_client.get(f"repo_path:{cve_id}")
#     repo_path = json.loads(repo_path_json)
#     cve_desc_json = redis_client.get(f"cve_desc:{cve_id}")
#     cve_desc = json.loads(cve_desc_json)
#     repo_url_json = redis_client.get(f"repo_url:{cve_id}")
#     repo_url = json.loads(repo_url_json)
#
#     task = process_commits.apply_async(args=[g_hashes, repo_path, cve_id, cve_desc, repo_url])
#     return jsonify({'task_id': task.id}), 202
#
#
# @app.route('/task_status/<task_id>')
# def task_status(task_id):
#     task = process_commits.AsyncResult(task_id)
#     if task.state == 'PROGRESS':
#         response = {'state': task.state, 'current': task.info.get('current', 0), 'total': task.info.get('total', 1)}
#     elif task.state != 'SUCCESS':
#         response = {'state': task.state}
#     else:
#         response = {'state': task.state, 'result': task.result}
#     print(response)
#     return jsonify(response)
#
#
# # Flask endpoints
# @app.route('/process_cves', methods=['POST'])
# def submit_cve_task():
#     data = request.json
#     cve_ids = data.get("cve_ids", [])
#     if not cve_ids:
#         return jsonify({"error": "No CVE IDs provided"}), 400
#
#     task = automated_fix_miner.apply_async(args=[cve_ids])
#     return jsonify({"task_id": task.id}), 202
