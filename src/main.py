import base64
import json
import logging
import os
import signal
import sys
import time

import pyotp
from synology_api.core_certificate import Certificate

SYNO_HELPER_HOST = os.environ["SYNO_HELPER_HOST"]
SYNO_HELPER_PORT = os.getenv("SYNO_HELPER_PORT", "5000")
SYNO_HELPER_USER = os.environ["SYNO_HELPER_USER"]
SYNO_HELPER_PWD = os.environ["SYNO_HELPER_PWD"]
SYNO_HELPER_OTP = os.getenv("SYNO_HELPER_OTP")
SYNO_HELPER_CERT_DESC = os.getenv("SYNO_HELPER_CERT_DESC", "default")
SYNO_HELPER_ACME_PATH = os.environ["SYNO_HELPER_ACME_PATH"]
SYNO_HELPER_ACME_RESOLVER = os.environ["SYNO_HELPER_ACME_RESOLVER"]
SYNO_HELPER_ACME_CERT_DOMAIN = os.environ["SYNO_HELPER_ACME_CERT_DOMAIN"]

logging.basicConfig(
    format="[%(asctime)s] %(message)s",
    level=logging.INFO,
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)


class GracefulKiller:
    kill_now = False

    def __init__(self):
        signal.signal(signal.SIGINT, self.exit_gracefully)
        signal.signal(signal.SIGTERM, self.exit_gracefully)

    def exit_gracefully(self, *args):
        self.kill_now = True


def gen_cert_from_acme(acme_path: str, resolver: str, domain: str) -> tuple[str, str]:
    logger.info("exporting certificates from %r", acme_path)
    content: dict
    with open(acme_path, "r") as f:
        content = json.loads(f.read())
    if not content:
        sys.exit("failed to not found {}".format(acme_path))

    logger.info("find resolver from %r", resolver)
    serv_key = os.path.join(os.getcwd(), "server.key")
    ser_cert = os.path.join(os.getcwd(), "server.crt")
    for cert in content[resolver]["Certificates"]:
        if cert["domain"]["main"] == domain:
            with open(ser_cert, "w") as ff:
                ff.write(base64.b64decode(cert["certificate"]).decode("utf-8"))
            with open(serv_key, "w") as ff:
                ff.write(base64.b64decode(cert["key"]).decode("utf-8"))
            break

    logger.info("generating key: %r crt: %r", serv_key, ser_cert)
    return serv_key, ser_cert


def get_exists_cert_id(cert_api: Certificate, desc: str) -> str:
    if not desc:
        logger.warning("skip looking for existing certificates. Because the desc is empty.", desc)
        return None

    result = cert_api.list_cert()
    if (not result["success"]) or (not result["data"]) or (not result["data"]["certificates"]):
        sys.exit("failed to fetch data by synology: {}".format(result))

    for cert in result["data"]["certificates"]:
        if cert["desc"] == desc:
            return cert["id"]

    logger.warning("cannot find desc: %r", desc)
    return None


def login_cert_api() -> Certificate:
    opt_code = None
    if SYNO_HELPER_OTP:
        opt: pyotp.TOTP = pyotp.parse_uri(SYNO_HELPER_OTP)
        opt_code = opt.now()
    return Certificate(SYNO_HELPER_HOST,
                       SYNO_HELPER_PORT,
                       SYNO_HELPER_USER,
                       SYNO_HELPER_PWD,
                       secure=False,
                       cert_verify=False,
                       dsm_version=7,
                       debug=True,
                       otp_code=opt_code)


def renew_cert():
    serv_key, ser_cert = gen_cert_from_acme(SYNO_HELPER_ACME_PATH, SYNO_HELPER_ACME_RESOLVER,
                                            SYNO_HELPER_ACME_CERT_DOMAIN)

    cert_api = login_cert_api()
    cert_id = get_exists_cert_id(cert_api, SYNO_HELPER_CERT_DESC)
    result = cert_api.upload_cert(serv_key,
                                  ser_cert,
                                  cert_id=cert_id,
                                  desc=(SYNO_HELPER_CERT_DESC if cert_id else "default"))
    logger.info("updating result: %r", result)

    cert_api.logout()
    os.remove(serv_key)
    os.remove(ser_cert)
    logger.info("cleaning up environments")


def main():
    killer = GracefulKiller()
    last_modified_time: float = 0
    while not killer.kill_now:
        current_modified_time = os.stat(SYNO_HELPER_ACME_PATH).st_mtime
        if current_modified_time > last_modified_time:
            logger.info("found that the file has changed(%r > %r), and started to update the certificate",
                        current_modified_time,
                        last_modified_time)
            renew_cert()

            logger.info("set current_modified_time: %r, to last_modified_time", current_modified_time)
            last_modified_time = current_modified_time
        if not killer.kill_now:
            logger.info("sleep for 5 seconds to check next step")
            time.sleep(5)

    logger.warning("shutdown...")


if __name__ == "__main__":
    main()
