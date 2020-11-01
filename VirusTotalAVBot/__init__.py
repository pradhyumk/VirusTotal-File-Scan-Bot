import os

BOT_TOKEN = os.environ.get('BOT_TOKEN')
API_ID = int(os.environ.get('API_ID'))
API_HASH = os.environ.get('API_HASH')
BOT_USERNAME = os.environ.get('BOT_USERNAME')
BOT_OWNER = os.environ.get('BOT_OWNER')
PLUG_IN = dict(root="VirusTotalAVBot.modules")
VT_API = os.environ.get('VT_API')
GROUP_INFO_MSGS = os.environ.get('GROUP_INFO_MSGS')
MAX_FILE_SIZE = int(os.environ.get('MAX_FILE_SIZE'))
