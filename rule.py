import configparser
from adblockparser import AdblockRules
from urllib import request
import logging
config = configparser.ConfigParser()
config.read("config.conf")
website = config["REJECT"]["website"]
logger = logging.getLogger(__name__)
try:
    rulesfile = request.urlopen(website)
    raw_rules = [i for i in str(rulesfile.read(), "utf-8").split("\n")]
    logger.info("read rules from %s" % website)
except Exception as e:
    raw_rules = [i for i in open("easylist.txt", encoding="utf-8").read().split("\n")]
    # logger.exception(e)
    logger.error(("can not read rules form %s, using local rules" % website))

rules = AdblockRules(raw_rules)

def what_rule(url):
    if rules.should_block(url):
        return "REJECT"
    else:
        return "DIRECT"
