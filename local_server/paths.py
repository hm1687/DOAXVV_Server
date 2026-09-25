# paths.py — 路径与文件常量 (从 local_server_v2.py 提取, 行为不变)
# __file__ 在本目录 = local_server/, 与原 local_server_v2.py 同目录, 故 OUT 不变
import os

OUT = os.path.dirname(os.path.abspath(__file__))
CERT = os.path.join(OUT, "doaxvv_cert.pem")
KEY = os.path.join(OUT, "doaxvv_key.pem")
LOG = os.path.join(OUT, "full_server.log")
GM_HTML = os.path.normpath(os.path.join(OUT, "..", "GM", "gm_panel.html"))
RSA_PUB = os.path.join(OUT, "rsa_server_pub.pem")
RSA_PRIV = os.path.join(OUT, "rsa_server_priv.pem")
TOOL = os.path.normpath(os.path.join(OUT, ".."))
CSV_LIST_JSON = os.path.join(TOOL, "real_csv_list.json")
CSV_MASTER = os.path.join(TOOL, "csv_master")
