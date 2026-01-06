import base64
import gzip
import sys

# 尝试导入 pycryptodome 库用于 AES 加密
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    print("Warning: 'pycryptodome' library not found. AES encryption will not work.")
    print("Please install it using: pip install pycryptodome")

class CryptoTool:
    def __init__(self, key_string, iv_string=None):
        """
        初始化加密工具
        :param key_string: 密钥字符串 (AES-128必须是16字节)
        :param iv_string: 初始化向量字符串 (必须是16字节)
        """
        self.key = key_string.encode('utf-8')
        if len(self.key) != 16:
             # 简单处理：如果不是16位，可能需要调整，这里暂时保持原样或报错
             pass

        self.fixed_iv = None
        if iv_string:
            self.fixed_iv = iv_string.encode('utf-8')
            if len(self.fixed_iv) != 16:
                raise ValueError("IV must be exactly 16 bytes long.")

        # 定义操作映射表
        # key: (加密函数, 解密函数)
        self.operations = {
            "101": (self._gzip_encrypt, self._gzip_decrypt),   # GZIP
            "1001": (self._aes_encrypt, self._aes_decrypt),    # AES
            "-999": (self._base64_encrypt, self._base64_decrypt) # Base64
        }

    # ================= 基础操作函数 (输入输出均为 bytes) =================

    def _gzip_encrypt(self, data: bytes) -> bytes:
        return gzip.compress(data)

    def _gzip_decrypt(self, data: bytes) -> bytes:
        return gzip.decompress(data)

    def _aes_encrypt(self, data: bytes) -> bytes:
        if not HAS_CRYPTO: raise ImportError("pycryptodome not installed")
        if not self.fixed_iv: raise ValueError("IV is required for AES")
        
        cipher = AES.new(self.key, AES.MODE_CBC, self.fixed_iv)
        return cipher.encrypt(pad(data, AES.block_size))

    def _aes_decrypt(self, data: bytes) -> bytes:
        if not HAS_CRYPTO: raise ImportError("pycryptodome not installed")
        if not self.fixed_iv: raise ValueError("IV is required for AES")

        cipher = AES.new(self.key, AES.MODE_CBC, self.fixed_iv)
        return unpad(cipher.decrypt(data), AES.block_size)

    def _base64_encrypt(self, data: bytes) -> bytes:
        return base64.b64encode(data)

    def _base64_decrypt(self, data: bytes) -> bytes:
        return base64.b64decode(data)

    # ================= 通用处理流程 =================

    def run_pipeline(self, data, config_str, is_encrypt=True):
        """
        执行通用管道处理
        :param data: 输入数据 (str 或 bytes)
        :param config_str: 配置字符串，如 "101,1001,-999"
        :param is_encrypt: True为加密，False为解密
        :return: 结果 (通常是 str 或 bytes)
        """
        # 1. 解析配置
        steps = [s.strip() for s in config_str.split(',')]
        
        # 如果是解密，步骤需要反转 (例如: Base64解密 -> AES解密 -> GZIP解压)
        if not is_encrypt:
            steps = list(reversed(steps))

        # 2. 统一转换为 bytes 处理
        current_data = data
        if isinstance(current_data, str):
            current_data = current_data.encode('utf-8')

        # 3. 依次执行步骤
        for step_code in steps:
            if not step_code: continue
            
            if step_code not in self.operations:
                print(f"Warning: Unknown operation code '{step_code}', skipping.")
                continue

            enc_func, dec_func = self.operations[step_code]
            func = enc_func if is_encrypt else dec_func
            
            try:
                current_data = func(current_data)
            except Exception as e:
                print(f"Error during step {step_code} ({'encrypt' if is_encrypt else 'decrypt'}): {e}")
                return None

        # 4. 结果处理
        # 如果是加密，且最后一步是 Base64，通常返回字符串
        if is_encrypt and steps[-1] == "-999":
            return current_data.decode('utf-8')
        
        # 如果是解密，通常期望变回原始字符串
        if not is_encrypt:
            try:
                return current_data.decode('utf-8')
            except UnicodeDecodeError:
                # 如果解密结果不是文本（比如解密了一半），返回 bytes
                return current_data
        
        return current_data

    def encrypt(self, raw_data, config_str="101,1001,-999"):
        return self.run_pipeline(raw_data, config_str, is_encrypt=True)

    def decrypt(self, enc_data, config_str="101,1001,-999"):
        return self.run_pipeline(enc_data, config_str, is_encrypt=False)

if __name__ == "__main__":
    if not HAS_CRYPTO:
        sys.exit(1)

    # 配置
    my_secret_key = "8iuaKct.PMN38!!1"
    my_iv = "abcdefghijk1mnop"
    
    # 这里的 config 代表：先GZIP(101)，再AES(1001)，最后Base64(-999)
    # 解密时会自动反向：先Base64解，再AES解，最后GZIP解
    config = "101,1001,-999"

    tool = CryptoTool(my_secret_key, iv_string=my_iv)

    # 测试数据 (JSON字符串)
    original_text = """{"update":{"version":"5e9e344f9e4163c9e0d23dd727810216","checkInterval":60000,"expireTime":1800000,"maxExpireTime":36000000},"requestUrl":{"configUrl":"http://sdk-api.adn-plus.com.cn/api/v3/cfg/getConfig","adUrl":"http://sdk-api.adn-plus.com.cn/api/v3/ad/getAd","version":"32460925cc0ff5772ef919b1932f9832"},"logStrategy":{"acceptEncrypt":"101,1001","customData":"","event":[{"codes":["100.000","100.200","100.500","200.000","250.000","250.200","250.500","260.000","260.200","260.500","270.000","270.200","270.201","280.200","280.201","290.000"],"uploadUrl":"http://sdk-event.beizi.biz/v2/api/adn/sdk/log","level":[],"count":1,"time":"10000","sample":100}],"version":"c189fe16bc05ea0d101e6cd4fe86377f","customId":"adn","crash":{"close":0,"url":"http://sdk-event.beizi.biz/v2/api/adn/crash/log"}}"""
    print(f"Original: {original_text}")
    print(f"Config: {config}")

    # 加密
    encrypted_text = tool.encrypt(original_text,config)
    print(f"\nEncrypted Result: {encrypted_text}")

    # 解密
    encrypted_text_me = """eE2kxWEKipl5a894z/gwu1yhoflZxhdyByDOKniRg6yLrSaQ+Vglx/euk0DgMxp8IbYmsBNvFBlPzBV1QkD9wR1pCQvIaZAgMe7abxCS+HjsXTUkCJZ0/FC3y5oIoouAYcZfufJet/46z4d4ZUw/iyUJBByMcNbnMG8L7a8ZlIL2ewlH8830GglIu0g4q9OvrcnFJwPYf2x1T7yksVmHlnWIudOtV0to9uhMmL6AEiWFPF7e2m8Jrhs4GY5cXqfz4K6wXiTy4n7xkT3GqxaLOitaW/DL/rs2aPy33NHIgC3DEIepM9znVy8P4ci2GPg9xO7q1iij4SItlYvtZ6KKIgf9n1dA0cZSqH5LZmnlBAna+XjD/fT/cqPalQozFGbAUU5myCMgWz343DhrfhQmhtjSAxkGpYRD0/wGjgRODm6IyNCQOxWNYhv4Gn3hmF3P+IJasdE7k+ZHgQJvwYQB3l79U1ghlA/uyxqDNGlIzimPU0vJwMnh8ntivwfgUWOv/nl5x8Z1uVCWZEUe8uC6ObqrQ9LED8aCxH/0mBSxMh8WrZgAetbA7uaHzajPhYXzG57aXuYugYkdHePiGNTswhNAbA0DsW95HOn6wcx880A="""
    decrypted_text = tool.decrypt(encrypted_text_me, config)
    print(f"\nDecrypted Result: {decrypted_text}")
    
    # 验证
    if original_text == decrypted_text:
        print("\nVerification Successful!")
    else:
        print("\nVerification Failed!")
