class AppConfig:
    OPENAI_API_KEY = <YOUR_OPENAI_API_KEY>
    Google_PROJECT_ID = <YOUR_Google_PROJECT_ID>
    GITHUB_TOKEN = <YOUR_GITHUB_PAT_TOKEN> # Needed for GitHub API for retrieving data.
    GEMINI_MODEL = "gemini-1.5-flash-002" # Your can change to other models from Google as well, however, we have not tested it.
    LOCATION = "australia-southeast1"
    DICTIONARY_PATTERN = r'\{(?:[^{}]++|(?R))*\}'
    VERSION_PATTERN = r'\d+\.\d+\.\d+'
