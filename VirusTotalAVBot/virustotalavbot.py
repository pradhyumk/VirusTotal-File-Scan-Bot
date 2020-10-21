from pyrogram import Client
from VirusTotalAVBot import API_ID, API_HASH, BOT_TOKEN, PLUG_IN
import logging

logger = logging.getLogger(__name__)


class VirusTotalAVBot(Client):
    def __init__(self):
        logger.info("Creating Bot Session")
        super().__init__(session_name=":memory:", bot_token=BOT_TOKEN, api_id=API_ID, api_hash=API_HASH,
                         plugins=PLUG_IN)

    async def start(self):
        await super().start()

    async def stop(self, *args):
        await super().stop()
