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
        if is_encrypt and steps[-1] == "-999":
            return current_data.decode('utf-8')
        
        if not is_encrypt:
            try:
                return current_data.decode('utf-8')
            except UnicodeDecodeError:
                return current_data
        
        return current_data

    def encrypt(self, raw_data, config_str="101,1001,-999"):
        return self.run_pipeline(raw_data, config_str, is_encrypt=True)

    def decrypt(self, enc_data, config_str="101,1001,-999"):
        return self.run_pipeline(enc_data, config_str, is_encrypt=False)

def run_gui(tool):
    """启动图形化界面"""
    import tkinter as tk
    from tkinter import scrolledtext, messagebox
    from tkinter import font as tkfont

    # --- 颜色主题配置 (极简黑白灰 + 莫兰迪色) ---
    COLOR_BG = "#F9F9F9"          # 极浅的灰白背景
    COLOR_FRAME_BG = "#FFFFFF"    # 纯白卡片
    
    COLOR_BTN_ENC = "#333333"     # 加密：深灰
    COLOR_BTN_ENC_HOVER = "#555555"
    
    COLOR_BTN_DEC = "#78909C"     # 解密：蓝灰
    COLOR_BTN_DEC_HOVER = "#90A4AE"

    COLOR_BTN_CLEAR = "#E0E0E0"   # 清空：浅灰
    COLOR_BTN_CLEAR_HOVER = "#BDBDBD"
    COLOR_BTN_CLEAR_TEXT = "#666666"

    COLOR_TEXT = "#2C3E50"        # 深蓝灰文字
    COLOR_TEXT_LIGHT = "#95A5A6"  # 浅灰说明文字
    COLOR_BORDER = "#EEEEEE"      # 极淡的边框
    
    FONT_FAMILY = "Microsoft YaHei UI" 
    
    window = tk.Tk()
    window.title("Ad Tools Crypto")
    window.geometry("800x650")
    window.configure(bg=COLOR_BG)

    # 自定义字体
    title_font = tkfont.Font(family=FONT_FAMILY, size=11, weight="bold")
    normal_font = tkfont.Font(family=FONT_FAMILY, size=10)
    code_font = tkfont.Font(family="Consolas", size=10)

    # --- 顶部配置区域 ---
    frame_top = tk.Frame(window, bg=COLOR_FRAME_BG, padx=20, pady=15)
    frame_top.pack(fill=tk.X, padx=15, pady=(15, 10))
    frame_top.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    tk.Label(frame_top, text="加密流程配置 (Config):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W)
    tk.Label(frame_top, text="101=GZIP, 1001=AES, -999=Base64 (逗号分隔)", font=normal_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT_LIGHT).pack(anchor=tk.W, pady=(2, 5))

    entry_config = tk.Entry(frame_top, font=code_font, bg="#FAFAFA", fg=COLOR_TEXT, relief="flat", highlightthickness=1, highlightbackground=COLOR_BORDER)
    entry_config.insert(0, "101,1001,-999")
    entry_config.pack(fill=tk.X, ipady=5)

    # --- 中间输入区域 ---
    frame_mid = tk.Frame(window, bg=COLOR_BG)
    frame_mid.pack(fill=tk.BOTH, expand=True, padx=15)

    frame_input = tk.Frame(frame_mid, bg=COLOR_FRAME_BG, padx=15, pady=10)
    frame_input.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
    frame_input.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    # 标题栏加一个清空按钮
    frame_input_header = tk.Frame(frame_input, bg=COLOR_FRAME_BG)
    frame_input_header.pack(fill=tk.X, pady=(0, 5))
    
    tk.Label(frame_input_header, text="输入内容 (Input):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(side=tk.LEFT)
    
    def clear_input():
        text_input.delete("1.0", tk.END)

    btn_clear_in = tk.Button(frame_input_header, text="清空", command=clear_input,
                             font=normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT,
                             activebackground=COLOR_BTN_CLEAR_HOVER, relief="flat", cursor="hand2",
                             padx=10, pady=0)
    btn_clear_in.pack(side=tk.RIGHT)

    text_input = scrolledtext.ScrolledText(frame_input, height=8, font=normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
    text_input.pack(fill=tk.BOTH, expand=True)
    text_input.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)

    # --- 按钮区域 ---
    frame_btns = tk.Frame(window, bg=COLOR_BG)
    frame_btns.pack(fill=tk.X, padx=15, pady=5)

    def create_btn(parent, text, command, bg_color, hover_color, text_color="white"):
        btn = tk.Button(parent, text=text, command=command, 
                        font=title_font, 
                        bg=bg_color, 
                        fg=text_color, 
                        activebackground=hover_color, 
                        activeforeground=text_color,
                        relief="flat", 
                        cursor="hand2",
                        width=15,
                        pady=6)
        return btn

    def on_encrypt():
        content = text_input.get("1.0", tk.END).strip()
        cfg = entry_config.get().strip()
        if not content:
            messagebox.showwarning("提示", "请输入需要加密的内容")
            return
        
        try:
            result = tool.encrypt(content, cfg)
            text_output.delete("1.0", tk.END)
            if result is None:
                text_output.insert(tk.END, "Encryption Failed (Check console for details)")
            else:
                text_output.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def on_decrypt():
        content = text_input.get("1.0", tk.END).strip()
        cfg = entry_config.get().strip()
        if not content:
            messagebox.showwarning("提示", "请输入需要解密的内容")
            return
        
        try:
            result = tool.decrypt(content, cfg)
            text_output.delete("1.0", tk.END)
            if result is None:
                text_output.insert(tk.END, "Decryption Failed (Check console for details)")
            else:
                if isinstance(result, bytes):
                    text_output.insert(tk.END, f"[Binary Data]: {result}")
                else:
                    text_output.insert(tk.END, result)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def clear_all():
        text_input.delete("1.0", tk.END)
        text_output.delete("1.0", tk.END)

    frame_btn_center = tk.Frame(frame_btns, bg=COLOR_BG)
    frame_btn_center.pack()
    
    btn_enc = create_btn(frame_btn_center, "加密 (Encrypt)", on_encrypt, COLOR_BTN_ENC, COLOR_BTN_ENC_HOVER)
    btn_enc.pack(side=tk.LEFT, padx=10)
    
    btn_dec = create_btn(frame_btn_center, "解密 (Decrypt)", on_decrypt, COLOR_BTN_DEC, COLOR_BTN_DEC_HOVER)
    btn_dec.pack(side=tk.LEFT, padx=10)

    # 底部大清空按钮
    btn_clear_all = create_btn(frame_btn_center, "全部清空", clear_all, COLOR_BTN_CLEAR, COLOR_BTN_CLEAR_HOVER, COLOR_BTN_CLEAR_TEXT)
    btn_clear_all.pack(side=tk.LEFT, padx=10)

    # --- 底部输出区域 ---
    frame_output = tk.Frame(window, bg=COLOR_FRAME_BG, padx=15, pady=10)
    frame_output.pack(fill=tk.BOTH, expand=True, padx=15, pady=(10, 15))
    frame_output.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    # 输出区标题栏
    frame_out_header = tk.Frame(frame_output, bg=COLOR_FRAME_BG)
    frame_out_header.pack(fill=tk.X, pady=(0, 5))

    tk.Label(frame_out_header, text="输出结果 (Output):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(side=tk.LEFT)
    
    def clear_output():
        text_output.delete("1.0", tk.END)

    btn_clear_out = tk.Button(frame_out_header, text="清空", command=clear_output,
                             font=normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT,
                             activebackground=COLOR_BTN_CLEAR_HOVER, relief="flat", cursor="hand2",
                             padx=10, pady=0)
    btn_clear_out.pack(side=tk.RIGHT)
    
    text_output = scrolledtext.ScrolledText(frame_output, height=8, font=normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
    text_output.pack(fill=tk.BOTH, expand=True)
    text_output.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)

    window.mainloop()

if __name__ == "__main__":
    if not HAS_CRYPTO:
        sys.exit(1)

    # 配置
    my_secret_key = "8iuaKct.PMN38!!1"
    my_iv = "abcdefghijk1mnop"

    tool = CryptoTool(my_secret_key, iv_string=my_iv)

    # 启动图形界面
    print("Starting GUI...")
    run_gui(tool)
