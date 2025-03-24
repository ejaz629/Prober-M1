class Config:
    REDIS_URL = "redis://localhost:6379" # only when running on local machine.
    CELERY_BROKER_URL = 'redis://localhost:6379/0'
    CELERY_RESULT_BACKEND = 'redis://localhost:6379/0'

    # REDIS_URL = "redis://redis:6379"  # Docker container Redis URL
    # CELERY_BROKER_URL = 'redis://redis:6379/0'  # Use the same Redis container for the broker
    # CELERY_RESULT_BACKEND = 'redis://redis:6379/0'  # Use Redis container for result backend
    # USER_OPTIONS = {}


class AppConfig:
    OUTPUT_DIR = "repos"
    DIFF_SIZE_THRESHOLD = 50
    GEMINI_MODEL = "gemini-1.5-flash-002"
    TOP_K = 10
    DICTIONARY_PATTERN = r'\{(?:[^{}]++|(?R))*\}'
    VERSION_PATTERN = r'\d+\.\d+\.\d+'
    # github_token = "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"
    github_token = "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"
