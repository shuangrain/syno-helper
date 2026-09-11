import base64
import json
import logging
import os
import re
import signal
import sys
import time
from typing import Any

import pyotp
import requests
from cryptography.hazmat.primitives import serialization
from synology_api.core_certificate import Certificate

SYNO_HELPER_HOST = os.environ["SYNO_HELPER_HOST"]
SYNO_HELPER_PORT = os.getenv("SYNO_HELPER_PORT", "5000")
SYNO_HELPER_USER = os.environ["SYNO_HELPER_USER"]
SYNO_HELPER_PWD = os.environ["SYNO_HELPER_PWD"]
SYNO_HELPER_OTP = os.getenv("SYNO_HELPER_OTP")
SYNO_HELPER_CERT_DESC = os.getenv("SYNO_HELPER_CERT_DESC", "default")
SYNO_HELPER_SET_AS_DEFAULT = os.getenv("SYNO_HELPER_SET_AS_DEFAULT", "false").lower() in ("true", "1", "yes")
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


def normalize_key_pem(key_str: str) -> str:
    """將私鑰轉換為 Synology DSM 最相容的 Traditional OpenSSL 格式 (PKCS#1 / SEC1)"""
    try:
        key = serialization.load_pem_private_key(key_str.encode("utf-8"), password=None)
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
    except Exception as e:
        logger.warning("could not convert key to traditional format (%s), keeping original", e)
        return key_str


def gen_cert_from_acme(acme_path: str, resolver: str, domain: str) -> tuple[str, str, str | None]:
    logger.info("exporting certificates from %r", acme_path)
    with open(acme_path) as f:
        content = json.loads(f.read())
    if not content:
        sys.exit(f"failed to read {acme_path}")

    logger.info("find resolver from %r", resolver)
    serv_key = os.path.join(os.getcwd(), "server.key")
    ser_cert = os.path.join(os.getcwd(), "server.crt")
    inter_cert = os.path.join(os.getcwd(), "intermediate.crt")
    has_inter = False

    for cert in content[resolver]["Certificates"]:
        if cert["domain"]["main"] == domain:
            cert_raw = base64.b64decode(cert["certificate"]).decode("utf-8")
            key_raw = base64.b64decode(cert["key"]).decode("utf-8")

            # 將私鑰轉換為 Traditional OpenSSL 格式
            key_pem = normalize_key_pem(key_raw)

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
                ff.write(key_pem)
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


def upload_cert_to_synology(
    cert_api: Certificate,
    serv_key: str,
    ser_cert: str,
    ca_cert: str | None = None,
    cert_id: str | None = None,
    desc: str | None = None,
    set_as_default: bool = False,
) -> tuple[int, dict[str, Any]]:
    """比照 acme.sh 實作更健壯的 Synology DSM 憑證上傳請求"""
    api_name = "SYNO.Core.Certificate"
    info = cert_api.session.app_api_list[api_name]
    api_path = info["path"]
    min_version = info["minVersion"]

    # 取得帶有認證 Cookies 的 requests.Session
    session = getattr(cert_api.session, "_requests_session", None) or requests.Session()
    syno_token = getattr(cert_api.session, "_syno_token", None)

    # 構建 URL：同時帶入 _sid 與 SynoToken (滿足 DSM 7 CSRF 防護)
    url = f"{cert_api.base_url}{api_path}?api={api_name}&version={min_version}&method=import&_sid={cert_api._sid}"
    if syno_token:
        url += f"&SynoToken={syno_token}"

    data_payload: dict[str, str] = {
        "id": cert_id or "",
        "desc": desc or "",
    }
    if set_as_default:
        data_payload["as_default"] = "true"

    headers = {}
    if syno_token:
        headers["X-SYNO-TOKEN"] = syno_token

    # 檔案名稱使用 basename，避免路徑中的斜線觸發 Synology upload_err 檢驗錯誤
    f_key = open(serv_key, "rb")
    f_cert = open(ser_cert, "rb")
    f_ca = None

    try:
        files: dict[str, Any] = {
            "key": (os.path.basename(serv_key), f_key, "application/octet-stream"),
            "cert": (os.path.basename(ser_cert), f_cert, "application/octet-stream"),
        }
        if ca_cert and os.path.exists(ca_cert):
            f_ca = open(ca_cert, "rb")
            files["inter_cert"] = (os.path.basename(ca_cert), f_ca, "application/octet-stream")

        r = session.post(
            url,
            files=files,
            data=data_payload,
            headers=headers,
            verify=cert_api.session.verify_cert_enabled(),
        )
        try:
            res_json = r.json()
        except Exception:
            res_json = {"raw_text": r.text}
        return r.status_code, res_json
    finally:
        f_key.close()
        f_cert.close()
        if f_ca:
            f_ca.close()


def renew_cert():
    serv_key, ser_cert, ca_cert = gen_cert_from_acme(
        SYNO_HELPER_ACME_PATH, SYNO_HELPER_ACME_RESOLVER, SYNO_HELPER_ACME_CERT_DOMAIN
    )

    cert_api = login_cert_api()
    cert_id = get_exists_cert_id(cert_api, SYNO_HELPER_CERT_DESC)
    target_desc = SYNO_HELPER_CERT_DESC or "default"

    status_code, result = upload_cert_to_synology(
        cert_api=cert_api,
        serv_key=serv_key,
        ser_cert=ser_cert,
        ca_cert=ca_cert,
        cert_id=cert_id,
        desc=target_desc,
        set_as_default=SYNO_HELPER_SET_AS_DEFAULT,
    )
    logger.info("updating result: (%r, %r)", status_code, result)

    # 若設定要設為預設憑證且上傳成功，將其設定為預設憑證
    if SYNO_HELPER_SET_AS_DEFAULT and result.get("success"):
        new_cert_id = cert_id or get_exists_cert_id(cert_api, target_desc)
        if new_cert_id:
            try:
                set_res = cert_api.set_default_cert(new_cert_id)
                logger.info("set default cert result: %r", set_res)
            except Exception as e:
                logger.warning("failed to set default cert: %s", e)

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
