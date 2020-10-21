from math import floor
from pyrogram import filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from .virustotal import replytofile, findhash, vthash, simplifiedview
from ..virustotalavbot import VirusTotalAVBot
import logging
import os

logger = logging.getLogger("info")

START_TEXT = ("Hey there! This bot scans files in the cloud without using your bandwidth!\n\n"
              "Some limitations:\nMaximum File Size - **200MB**\n\nBy using this bot, you adhere to VirusTotal's "
              "[Terms of Service](https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service) "
              "and their [Privacy Policy](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy)"
              "\n\nDisclaimer: This bot is not affiliated with [VirusTotal](https://virustotal.com/) in any way, and "
              "there is no guarantee this bot will remain online forever.")

HELP_MSG = '''Forward a file to scan with VirusTotal.\n\nMaximum File Size: **200MB**'''


@VirusTotalAVBot.on_message(filters.command('help', prefixes="/"))
async def helpcmd(client, message):
    await message.reply_text(HELP_MSG)


@VirusTotalAVBot.on_message(filters.command('start', prefixes="/"))
async def startcmd(client, message):
    instructions = [[InlineKeyboardButton(text="Instructions", callback_data="help")]]
    await message.reply_sticker(sticker="CAADAQADCQADSQrhLZWMmF8vQqpqFgQ")
    await message.reply_text(START_TEXT, quote=False, disable_web_page_preview=True,
                             reply_markup=InlineKeyboardMarkup(instructions))


@VirusTotalAVBot.on_message(filters.document)
def mediadetection(client, message):
    user = message.chat.id
    
    if not os.path.isdir('temp_download'):
        os.mkdir('temp_download/')

    msg = message.reply_text('Downloading your file...', quote=True)
    download_path = client.download_media(message=message, file_name='temp_download/', progress=progressbar,
                                          progress_args=("downloading", msg))
    logger.info(f"Downloaded File: {download_path}")

    response = replytofile(download_path, msg)
    print(response)
    msg.delete()  # Delete old reply, and send new one (for notification)

    filehash = findhash(download_path)
    vt_url = f'https://www.virustotal.com/gui/file/{filehash}'

    if response is None:
        response = f"__VirusTotal Analysis Summary__:\n\nHash: `{filehash}`\n\nLink: [Click Here]({vt_url})\n\nThis" \
                   f" file is still being analysed. Visit the link above or click \"Refresh Data\" after a minute to " \
                   f"check if your analysis results are ready"

        bttn = InlineKeyboardMarkup([[InlineKeyboardButton(text="Refresh Data", callback_data=f"refresh-{filehash}")]])
    else:
        bttn = InlineKeyboardMarkup([[InlineKeyboardButton(text="Detailed Analysis",
                                                           callback_data=f"detailed-{filehash}")]])

    client.send_message(chat_id=user, text=response, parse_mode='markdown', disable_web_page_preview=True,
                        reply_markup=bttn, reply_to_message_id=message.message_id)

    try:
        os.remove(download_path.replace('/', '//'))
    except OSError as e:
        logger.warning("File requested to be deleted does not exist!")


@VirusTotalAVBot.on_message(filters.command('checkhash', prefixes='/'))
def checkhash(client, message):
    """Provides information for a hash without uploading the file.\n
    File needs to be in VirusTotal's database for method to respond with useful information"""

    h = message.text
    h = h.split()[1]

    if vthash(h) is None:
        message.reply_text("This file has **not** been scanned on VirusTotal before.\n\n"
                           "You will need to send the file to view it's analysis results.", quote=True)
    else:
        response = simplifiedview(vthash(h), h)
        bttn = InlineKeyboardMarkup([[InlineKeyboardButton(text="Detailed Analysis", callback_data=f"detailed-{h}")]])
        message.reply_text(text=response, quote=True, parse_mode='markdown', disable_web_page_preview=True,
                           reply_markup=bttn)


async def progressbar(current, total, status: str, message):
    logger.info("Constructing Progressbar")
    if current == total:
        await message.edit_text("File has been downloaded!")
        return

    response = "Downloading your file... \n\n["
    percent_complete = round(((current / total) * 100), 2)

    for x in range(floor(percent_complete / 10)):
        response = response + "⚫"
    for x in range(10 - floor(percent_complete / 10)):
        response = response + "⚪"

    response = response + f"] {percent_complete}%"
    await message.edit_text(response)
