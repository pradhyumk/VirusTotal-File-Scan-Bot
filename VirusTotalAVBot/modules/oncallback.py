import logging

from pyrogram.errors import MessageNotModified
from pyrogram.types import InlineKeyboardButton, InlineKeyboardMarkup
from VirusTotalAVBot.modules.info import HELP_MSG, START_TEXT
from VirusTotalAVBot.modules.virustotal import detailedview, vthash, simplifiedview
from VirusTotalAVBot.virustotalavbot import VirusTotalAVBot

logger = logging.getLogger("Callback Methods")

@VirusTotalAVBot.on_callback_query()
async def onbuttonpress(client, message):
    callback_data = message.data

    # Handles generic call back data, for accessibility between the start screen and instructions

    if callback_data == 'help':
        logger.info("Help button pressed")
        button = [[InlineKeyboardButton(text="Go Back", callback_data="home")]]
        await message.edit_message_text(HELP_MSG, reply_markup=InlineKeyboardMarkup(button))

    elif callback_data == 'home':
        logger.info("Back button pressed")
        button = [[InlineKeyboardButton(text="Instructions", callback_data="help")]]
        await message.edit_message_text(START_TEXT, reply_markup=InlineKeyboardMarkup(button),
                                        disable_web_page_preview=True, parse_mode='markdown')

    # Will handle call back data received from buttons related to VirusTotal actions (reanalyse, etc)

    elif 'detailed' in callback_data:
        logger.info("User pressed \"Detailed Analysis\" button")
        filehash = callback_data.split('-')[1]
        bttn = InlineKeyboardMarkup(
            [[InlineKeyboardButton(text="Simplified Analysis", callback_data=f"simplified-{filehash}")],
             ])
        await message.edit_message_text(text=detailedview(vthash(filehash), filehash), disable_web_page_preview=True,
                                        reply_markup=bttn, parse_mode='markdown')

    elif 'simplified' in callback_data:
        logger.info("User pressed \"Simplified Analysis\" button")
        filehash = callback_data.split('-')[1]
        bttn = InlineKeyboardMarkup(
            [[InlineKeyboardButton(text="Detailed Analysis", callback_data=f"detailed-{filehash}")],
             ])
        await message.edit_message_text(text=simplifiedview(vthash(filehash), filehash), disable_web_page_preview=True,
                                        reply_markup=bttn, parse_mode='markdown')

    elif 'refresh' in callback_data:
        logger.info("User requested to refresh data")
        filehash = callback_data.split('-')[1]

        av_data = vthash(filehash)

        if av_data is not None:
            bttn = InlineKeyboardMarkup([[InlineKeyboardButton(text="Detailed Analysis",
                                                               callback_data=f"detailed-{filehash}")]])
            await message.edit_message_text(text=simplifiedview(av_data, filehash), disable_web_page_preview=True,
                                            reply_markup=bttn, parse_mode='markdown')
        else:
            vt_url = f'https://www.virustotal.com/gui/file/{filehash}'

            response = f"__VirusTotal Analysis Summary__:\n\nHash: `{filehash}`\n\nLink: [Click Here]({vt_url})" \
                       f"\n\nThis file is still being analysed. Visit the link above or click \"Refresh Data\" after " \
                       f"a minute to check if your analysis results are ready"

            bttn = InlineKeyboardMarkup([[InlineKeyboardButton(text="Refresh Data",
                                                               callback_data=f"refresh-{filehash}")]])
            try:
                await message.edit_message_text(text=response, parse_mode='markdown', disable_web_page_preview=True,
                                                reply_markup=bttn)
            except MessageNotModified as e:
                pass
