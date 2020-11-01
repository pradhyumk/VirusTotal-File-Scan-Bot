from math import floor
from pyrogram import filters
from pyrogram.types import InlineKeyboardMarkup, InlineKeyboardButton
from .virustotal import replytofile, findhash, vthash, simplifiedview
from .. import BOT_USERNAME, GROUP_INFO_MSGS, BOT_OWNER
from ..virustotalavbot import VirusTotalAVBot
import logging
import os

logger = logging.getLogger("info")

START_TEXT = ("Hey there! This bot scans files in the cloud without using your bandwidth!\n\n"
              "Some limitations:\nMaximum File Size - **200MB**\n\nThis bot will only be active for"
              " 22 days due to the Heroku free tier limitations\n\nBy using this bot, you adhere to VirusTotal's "
              "[Terms of Service](https://support.virustotal.com/hc/en-us/articles/115002145529-Terms-of-Service) "
              "and their [Privacy Policy](https://support.virustotal.com/hc/en-us/articles/115002168385-Privacy-Policy)"
              "\n\nDisclaimer: This bot is not affiliated with [VirusTotal](https://virustotal.com/) in any way, and "
              "there is no guarantee this bot will remain online forever.")

HELP_MSG = '''Forward a file to scan with VirusTotal.\n\nMaximum File Size: **200MB**'''

disable_in_groups = GROUP_INFO_MSGS


@VirusTotalAVBot.on_message(filters.command('help', prefixes="/") | filters.regex(f'/help@{BOT_USERNAME}'))
async def helpcmd(client, message):
    """Method responds with the help message."""
    # Some admins may believe /start and /help are spamming group chats, so they can be disabled.
    if disable_in_groups and (message.from_user.id != message.chat.id):
        return

    await message.reply_text(HELP_MSG)


@VirusTotalAVBot.on_message(filters.command('start', prefixes="/") | filters.regex(f'/start@{BOT_USERNAME}'))
async def startcmd(client, message):
    """Method responds with the start message"""

    # Some admins may believe /start and /help are spamming group chats, so they can be disabled.

    if disable_in_groups and (message.from_user.id != message.chat.id):
        return

    instructions = [[InlineKeyboardButton(text="Instructions", callback_data="help")]]
    await message.reply_sticker(sticker="CAADAQADCQADSQrhLZWMmF8vQqpqFgQ", quote=False)
    await message.reply_text(START_TEXT, quote=False, disable_web_page_preview=True,
                             reply_markup=InlineKeyboardMarkup(instructions))


@VirusTotalAVBot.on_message(filters.command('about', prefixes="/") | filters.regex(f'/about@{BOT_USERNAME}'))
async def aboutcmd(client, message):
    """Method responds with the about message"""

    MSG = "This bot is a research project made possible by VirusTotal, an Alphabet service which aggregates file scan" \
          " results various antivirus engines.\n\nInformation such as file hashes and scan results may be logged for" \
          f" academic research and debugging purposes only.\n\nDisclosure: This bot was forked by {BOT_OWNER} and the" \
          f" original source is linked below. You may create an issue in the original repository if there are any" \
          f" bugs with the source."

    instructions = [[InlineKeyboardButton(text="Original Bot Repository",
                                          url="https://github.com/pradhyumk/VirusTotal-File-Scan-Bot")]]

    await message.reply_text(MSG, quote=False, disable_web_page_preview=True,
                             reply_markup=InlineKeyboardMarkup(instructions))


@VirusTotalAVBot.on_message(filters.document)
def mediadetection(client, message):
    user = message.from_user.id
    chat = message.chat.id
    max_file_size = 419430400  # Maximum file size for documents the bot will positively respond to.
    if not os.path.isdir('temp_download'):
        os.mkdir('temp_download/')

    file_size = message.document.file_size

    if file_size > max_file_size:

        if message.from_user.id != message.chat.id:
            logger.info(f'User (ID: {user}) sent a file ({round(file_size / 1048576, 2)}MB) larger than the defined maximum'
                        f' file size ({round(max_file_size / 1048576, 2)}MB) in a group chat (ID: {message.chat.id}).')
            message.reply_text(f'Sorry, but this file is too large for us to process. Some engines may not process'
                               f' large files properly such as archives or even timeout after a certain period of time.'
                               f'\n\nBe cautious when downloading the file and upload smaller files inside the file'
                               f' if it is an archive.')

        else:
            logger.info(f'User ({user}) sent a file larger than the defined maximum file size'
                        f' ({round(max_file_size / 1048576, 2)}MB).')
            message.reply_text(f'Sorry, but this file is too large for us to process. Try sending a file under '
                               f'**{round(max_file_size / 1048576, 2)} MB**. \n\nOn a side note, some engines '
                               f'may not process large files such as archives or even timeout after a certain period of'
                               f' time. ')

        return

    msg = message.reply_text('__Downloading file...__', quote=True)

    if message.from_user.id != message.chat.id:
        download_path = client.download_media(message=message, file_name='temp_download/')
    else:
        download_path = client.download_media(message=message, file_name='temp_download/', progress=progressbar,
                                              progress_args=("downloading", msg))

    logger.info(f"Downloaded File: {download_path}")

    response = replytofile(download_path, msg)
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

    client.send_message(chat_id=chat, text=response, parse_mode='markdown', disable_web_page_preview=True,
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
