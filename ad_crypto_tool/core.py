# -*- coding: utf-8 -*-

import base64
import gzip
import json
import os

# 尝试导入 pycryptodome
try:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad, unpad
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

class CryptoTool:
    def __init__(self, key_string, iv_string=None):
        """
        初始化加密工具
        :param key_string: 密钥字符串 (AES-128必须是16字节)
        :param iv_string: 初始化向量字符串 (必须是16字节)
        """
        if not HAS_CRYPTO:
            raise ImportError("pycryptodome library not found. Please run: pip install pycryptodome")

        self.key = key_string.encode('utf-8')
        if len(self.key) != 16:
             # 实际项目中可能需要更严格的校验
             pass

        self.fixed_iv = None
        if iv_string:
            self.fixed_iv = iv_string.encode('utf-8')
            if len(self.fixed_iv) != 16:
                raise ValueError("IV must be exactly 16 bytes long.")

        # 定义操作映射表
        self.operations = {
            "101": (self._gzip_encrypt, self._gzip_decrypt),   # GZIP
            "1001": (self._aes_encrypt, self._aes_decrypt),    # AES
            "-999": (self._base64_encrypt, self._base64_decrypt) # Base64
        }

    # ================= 基础操作函数 =================

    def _gzip_encrypt(self, data: bytes) -> bytes:
        return gzip.compress(data)

    def _gzip_decrypt(self, data: bytes) -> bytes:
        return gzip.decompress(data)

    def _aes_encrypt(self, data: bytes) -> bytes:
        if not self.fixed_iv: raise ValueError("IV is required for AES")
        cipher = AES.new(self.key, AES.MODE_CBC, self.fixed_iv)
        return cipher.encrypt(pad(data, AES.block_size))

    def _aes_decrypt(self, data: bytes) -> bytes:
        if not self.fixed_iv: raise ValueError("IV is required for AES")
        cipher = AES.new(self.key, AES.MODE_CBC, self.fixed_iv)
        return unpad(cipher.decrypt(data), AES.block_size)

    def _base64_encrypt(self, data: bytes) -> bytes:
        return base64.b64encode(data)

    def _base64_decrypt(self, data: bytes) -> bytes:
        return base64.b64decode(data)

    # ================= 通用处理流程 =================

    def run_pipeline(self, data, config_str, is_encrypt=True):
        # 1. 解析配置
        steps = [s.strip() for s in config_str.split(',')]
        
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
        
        # 如果是解密，尝试转回字符串，失败则返回 bytes
        if not is_encrypt:
            try:
                return current_data.decode('utf-8')
            except UnicodeDecodeError:
                return current_data
        
        return current_data

    def encrypt(self, raw_data, config_str):
        return self.run_pipeline(raw_data, config_str, is_encrypt=True)

    def decrypt(self, enc_data, config_str):
        return self.run_pipeline(enc_data, config_str, is_encrypt=False)

    def process_file(self, input_path, output_path, config_str, is_encrypt=True):
        """处理文件流"""
        try:
            with open(input_path, 'rb') as f:
                raw_data = f.read()
            
            result = self.run_pipeline(raw_data, config_str, is_encrypt)
            
            if result is None:
                return False, "Processing failed inside pipeline", None

            # 写入结果
            with open(output_path, 'wb') as f:
                if isinstance(result, str):
                    f.write(result.encode('utf-8'))
                else:
                    f.write(result)
            
            # 尝试生成预览内容
            preview_content = None
            try:
                if isinstance(result, bytes):
                    # 尝试解码为 utf-8
                    preview_content = result.decode('utf-8')
                    # 尝试格式化 JSON (仅在解密时尝试)
                    if not is_encrypt:
                        try:
                            json_obj = json.loads(preview_content)
                            preview_content = json.dumps(json_obj, indent=4, ensure_ascii=False)
                        except:
                            pass 
                elif isinstance(result, str):
                    preview_content = result
            except:
                preview_content = "[Binary Data - Cannot Preview]"
            
            return True, f"Success! Saved to {output_path}", preview_content
        except Exception as e:
            return False, str(e), None
