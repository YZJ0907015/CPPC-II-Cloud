import socket
from mtlsp.transport import recv, send
import prnu
import secrets
import libnacl
from libnacl import utils
import logging
import os

# 配置日志
logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)

DEBUG = True

OK = b"\x55"
NOK = b"\xaa"

libnacl.sodium_init()

# 加载公私钥对
script_dir = os.path.dirname(os.path.abspath(__file__))
with open(script_dir+'/../../secret/key.sec', "rb") as f:
    seed = f.read()
ed_pk,ed_sk = libnacl.crypto_sign_seed_keypair(seed)
with open(script_dir+'/../../secret/key.pub', "rb") as f:
    ed_pkv = f.read()
if ed_pkv != ed_pk:
    raise ValueError('Public key not matched')

def handshake(conn: socket.socket,addr):
    try:
        # 接收 client_random
        client_random = recv(conn)
        assert len(client_random) == 32
        logging.info(f"client_random received: {client_random.hex()}")

        # 生成 server 随机数和 ECDH 密钥对
        server_random = secrets.token_bytes(32)  # server_random随机数
        server_eph_pub, server_eph_sec = (
            libnacl.crypto_kx_keypair()
        )  # 服务器临时 ECDH 公私钥对

        # 对 H(Q_s || client_random || server_random) 签名
        signature = libnacl.crypto_sign_detached(
            libnacl.crypto_hash_sha256(server_eph_pub + client_random + server_random),
            ed_sk,
        )

        # 发送 server_random, server_eph_pub, signature
        send(conn, server_random)
        send(conn, server_eph_pub)
        send(conn, signature)

        # 接收客户端加密的 Q_c || client_random || server_random
        boxed_msg = recv(conn)
        # 解密 Q_c || client_random || server_random
        x_sk = libnacl.crypto_sign_ed25519_sk_to_curve25519(ed_sk)
        x_pk = libnacl.crypto_sign_ed25519_pk_to_curve25519(ed_pk)
        decrypted = libnacl.crypto_box_seal_open(boxed_msg, x_pk, x_sk)
        # 验证 cr, sr
        client_eph_pub = decrypted[:32]
        cr_check = decrypted[32:64]
        sr_check = decrypted[64:96]
        if cr_check != client_random or sr_check != server_random:
            logging.error("Unexcepted cr,sr")
            conn.close()
            return
        logging.info("cr,sr confirmed，accept Q_c")

        # 使用客户端临时公钥发送 SealedBox(OK)
        boxed_ok = libnacl.crypto_box_seal(OK, client_eph_pub)
        send(conn, boxed_ok)

        # 计算预主密钥
        pre_master_secret = libnacl.crypto_box_beforenm(client_eph_pub, server_eph_sec)
        # 计算主密钥 M = H(Z || client_random || server_random)
        master_secret = libnacl.crypto_hash_sha256(
            pre_master_secret + client_random + server_random
        )

        logging.info(f"Master secret:{master_secret.hex()}")

        # 确认指纹信息
        nonce_client = recv(conn)
        enc_fingerprint = recv(conn)
        raw_fingerprint = libnacl.crypto_aead_aes256gcm_decrypt(
            enc_fingerprint, None, nonce_client, master_secret
        )
        if not prnu.verfiy_device(raw_fingerprint):
            logging.info("Device not matched")
            conn.close()
            return
        logging.info("Device matched")

        # 发送 OK 消息
        nonce_server = utils.rand_nonce()
        send(conn, nonce_server)
        final_ok = libnacl.crypto_aead_aes256gcm_encrypt(
            OK, None, nonce_server, master_secret
        )
        send(conn, final_ok)
        print("mtlsp handshake succeed!")
    except Exception as e:
        print(f"mtlsp handshake fail: {e}")
    finally:
        conn.close()
