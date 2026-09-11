import base64
import json
import logging
import os
import re
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


def gen_cert_from_acme(acme_path: str, resolver: str, domain: str) -> tuple[str, str, str | None]:
    logger.info("exporting certificates from %r", acme_path)
    with open(acme_path) as f:
        content = json.loads(f.read())
    if not content:
        sys.exit(f"failed to not found {acme_path}")

    logger.info("find resolver from %r", resolver)
    serv_key = os.path.join(os.getcwd(), "server.key")
    ser_cert = os.path.join(os.getcwd(), "server.crt")
    inter_cert = os.path.join(os.getcwd(), "intermediate.crt")
    has_inter = False

    for cert in content[resolver]["Certificates"]:
        if cert["domain"]["main"] == domain:
            cert_raw = base64.b64decode(cert["certificate"]).decode("utf-8")
            key_raw = base64.b64decode(cert["key"]).decode("utf-8")

            # 拆分 Domain Certificate 與 Intermediate Certificates
            cert_blocks = re.findall(
                r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                cert_raw,
                re.DOTALL,
            )

            if cert_blocks:
                with open(ser_cert, "w") as ff:
                    ff.write(cert_blocks[0] + "\n")
                if len(cert_blocks) > 1:
                    with open(inter_cert, "w") as ff:
                        ff.write("\n".join(cert_blocks[1:]) + "\n")
                    has_inter = True
            else:
                with open(ser_cert, "w") as ff:
                    ff.write(cert_raw)

            with open(serv_key, "w") as ff:
                ff.write(key_raw)
            break

    ca_cert = inter_cert if has_inter else None
    logger.info("generating key: %r crt: %r ca_cert: %r", serv_key, ser_cert, ca_cert)
    return serv_key, ser_cert, ca_cert


def get_exists_cert_id(cert_api: Certificate, desc: str) -> str | None:
    if not desc:
        logger.warning("skip looking for existing certificates because the desc is empty.")
        return None

    result = cert_api.list_cert()
    if (not result["success"]) or (not result["data"]) or (not result["data"]["certificates"]):
        sys.exit(f"failed to fetch data by synology: {result}")

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
    return Certificate(
        SYNO_HELPER_HOST,
        SYNO_HELPER_PORT,
        SYNO_HELPER_USER,
        SYNO_HELPER_PWD,
        secure=False,
        cert_verify=False,
        dsm_version=7,
        debug=True,
        otp_code=opt_code,
    )


def renew_cert():
    serv_key, ser_cert, ca_cert = gen_cert_from_acme(
        SYNO_HELPER_ACME_PATH, SYNO_HELPER_ACME_RESOLVER, SYNO_HELPER_ACME_CERT_DOMAIN
    )

    cert_api = login_cert_api()
    cert_id = get_exists_cert_id(cert_api, SYNO_HELPER_CERT_DESC)
    target_desc = SYNO_HELPER_CERT_DESC or "default"

    result = cert_api.upload_cert(
        serv_key=serv_key,
        ser_cert=ser_cert,
        ca_cert=ca_cert,
        cert_id=cert_id,
        desc=target_desc,
        set_as_default=True,
    )
    logger.info("updating result: %r", result)

    cert_api.logout()
    if os.path.exists(serv_key):
        os.remove(serv_key)
    if os.path.exists(ser_cert):
        os.remove(ser_cert)
    if ca_cert and os.path.exists(ca_cert):
        os.remove(ca_cert)
    logger.info("cleaning up environments")


def main():
    killer = GracefulKiller()
    last_modified_time: float = 0
    while not killer.kill_now:
        current_modified_time = os.stat(SYNO_HELPER_ACME_PATH).st_mtime
        if current_modified_time > last_modified_time:
            logger.info(
                "found that the file has changed(%r > %r), and started to update the certificate",
                current_modified_time,
                last_modified_time,
            )
            renew_cert()

            logger.info("set current_modified_time: %r, to last_modified_time", current_modified_time)
            last_modified_time = current_modified_time
        if not killer.kill_now:
            logger.info("sleep for 5 seconds to check next step")
            time.sleep(5)

    logger.warning("shutdown...")


if __name__ == "__main__":
    main()
