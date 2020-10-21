import logging
from pyrogram import Client, filters
from ..virustotalavbot import VirusTotalAVBot

logger = logging.getLogger("Debug Methods")


@VirusTotalAVBot.on_message(filters.sticker)
def stickerdata(client, message):
    logger.info(f"Received Sticker (ID: {message.sticker.file_id}) from {message.from_user.first_name} (ID"
                f": {message.from_user.id})")
