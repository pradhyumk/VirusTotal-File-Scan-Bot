import logging
from .virustotalavbot import VirusTotalAVBot

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                        datefmt='%m/%d/%Y %H:%M:%S')

    VirusTotalAVBot().run()
