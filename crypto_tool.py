import base64
import gzip
import sys
import os
import json

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
            
            # 尝试返回预览内容
            preview_content = None
            try:
                if isinstance(result, bytes):
                    # 尝试解码为 utf-8
                    preview_content = result.decode('utf-8')
                    # 尝试格式化 JSON (仅在解密时尝试，加密后的通常不是JSON)
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

def run_gui(tool):
    """启动图形化界面"""
    import tkinter as tk
    from tkinter import scrolledtext, messagebox, filedialog, ttk
    from tkinter import font as tkfont

    # --- 颜色主题配置 (极简黑白灰 + 莫兰迪色) ---
    COLOR_BG = "#F9F9F9"          
    COLOR_FRAME_BG = "#FFFFFF"    
    
    COLOR_BTN_ENC = "#333333"     
    COLOR_BTN_ENC_HOVER = "#555555"
    
    COLOR_BTN_DEC = "#78909C"     
    COLOR_BTN_DEC_HOVER = "#90A4AE"

    COLOR_BTN_CLEAR = "#E0E0E0"   
    COLOR_BTN_CLEAR_HOVER = "#BDBDBD"
    COLOR_BTN_CLEAR_TEXT = "#666666"

    COLOR_TEXT = "#2C3E50"        
    COLOR_TEXT_LIGHT = "#95A5A6"  
    COLOR_BORDER = "#EEEEEE"      
    
    FONT_FAMILY = "Microsoft YaHei UI" 
    
    window = tk.Tk()
    window.title("Ad Tools Crypto")
    window.geometry("900x750") 
    window.configure(bg=COLOR_BG)

    # 自定义字体
    title_font = tkfont.Font(family=FONT_FAMILY, size=11, weight="bold")
    normal_font = tkfont.Font(family=FONT_FAMILY, size=10)
    code_font = tkfont.Font(family="Consolas", size=10)

    # --- 顶部配置区域 (公共) ---
    frame_top = tk.Frame(window, bg=COLOR_FRAME_BG, padx=20, pady=15)
    frame_top.pack(fill=tk.X, padx=15, pady=(15, 10))
    frame_top.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    tk.Label(frame_top, text="加密流程配置 (Config):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W)
    tk.Label(frame_top, text="101=GZIP, 1001=AES, -999=Base64 (逗号分隔)", font=normal_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT_LIGHT).pack(anchor=tk.W, pady=(2, 5))

    entry_config = tk.Entry(frame_top, font=code_font, bg="#FAFAFA", fg=COLOR_TEXT, relief="flat", highlightthickness=1, highlightbackground=COLOR_BORDER)
    # 默认初始值 (Tab 0 - Text)
    entry_config.insert(0, "101,1001,-999")
    entry_config.pack(fill=tk.X, ipady=5)

    # --- 状态管理 (用于记住不同Tab的配置) ---
    # Index 0: Text Tab, Index 1: File Tab
    config_store = ["101,1001,-999", "101,1001"] 
    current_tab_index = [0] # 使用列表来存储可变整数引用

    def on_tab_change(event):
        """切换Tab时自动保存和加载配置"""
        # 1. 获取当前选中的Tab索引
        selected_tab_id = notebook.index(notebook.select())
        
        # 2. 保存旧Tab的配置
        old_tab_id = current_tab_index[0]
        config_store[old_tab_id] = entry_config.get()

        # 3. 加载新Tab的配置
        entry_config.delete(0, tk.END)
        entry_config.insert(0, config_store[selected_tab_id])

        # 4. 更新当前Tab索引
        current_tab_index[0] = selected_tab_id

    # --- 选项卡区域 ---
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
    style.configure("TNotebook.Tab", background="#E0E0E0", foreground=COLOR_TEXT, padding=[15, 5], font=normal_font)
    style.map("TNotebook.Tab", background=[("selected", COLOR_FRAME_BG)], foreground=[("selected", COLOR_BTN_ENC)])

    notebook = ttk.Notebook(window)
    notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)
    
    # 绑定Tab切换事件
    notebook.bind("<<NotebookTabChanged>>", on_tab_change)

    # === Tab 1: 文本处理 ===
    tab_text = tk.Frame(notebook, bg=COLOR_BG)
    notebook.add(tab_text, text="文本处理 (Text)")

    frame_input = tk.Frame(tab_text, bg=COLOR_FRAME_BG, padx=15, pady=10)
    frame_input.pack(fill=tk.BOTH, expand=True, pady=(10, 10))
    frame_input.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    frame_input_header = tk.Frame(frame_input, bg=COLOR_FRAME_BG)
    frame_input_header.pack(fill=tk.X, pady=(0, 5))
    tk.Label(frame_input_header, text="输入内容 (Input):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(side=tk.LEFT)
    
    text_input = scrolledtext.ScrolledText(frame_input, height=8, font=normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
    text_input.pack(fill=tk.BOTH, expand=True)
    text_input.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)
    
    def clear_input(): text_input.delete("1.0", tk.END)
    tk.Button(frame_input_header, text="清空", command=clear_input, font=normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT, relief="flat", cursor="hand2").pack(side=tk.RIGHT)

    # 文本按钮区
    frame_btns_text = tk.Frame(tab_text, bg=COLOR_BG)
    frame_btns_text.pack(fill=tk.X, pady=5)
    frame_btn_center_text = tk.Frame(frame_btns_text, bg=COLOR_BG)
    frame_btn_center_text.pack()

    def create_btn(parent, text, command, bg_color, hover_color, text_color="white"):
        btn = tk.Button(parent, text=text, command=command, font=title_font, bg=bg_color, fg=text_color, activebackground=hover_color, activeforeground=text_color, relief="flat", cursor="hand2", width=15, pady=6)
        return btn

    frame_output = tk.Frame(tab_text, bg=COLOR_FRAME_BG, padx=15, pady=10)
    frame_output.pack(fill=tk.BOTH, expand=True, pady=(10, 15))
    frame_output.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    frame_out_header = tk.Frame(frame_output, bg=COLOR_FRAME_BG)
    frame_out_header.pack(fill=tk.X, pady=(0, 5))
    tk.Label(frame_out_header, text="输出结果 (Output):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(side=tk.LEFT)
    
    text_output = scrolledtext.ScrolledText(frame_output, height=8, font=normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
    text_output.pack(fill=tk.BOTH, expand=True)
    text_output.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)

    def clear_output(): text_output.delete("1.0", tk.END)
    tk.Button(frame_out_header, text="清空", command=clear_output, font=normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT, relief="flat", cursor="hand2").pack(side=tk.RIGHT)

    def on_encrypt_text():
        content = text_input.get("1.0", tk.END).strip()
        cfg = entry_config.get().strip()
        if not content: return messagebox.showwarning("提示", "请输入内容")
        try:
            result = tool.encrypt(content, cfg)
            text_output.delete("1.0", tk.END)
            text_output.insert(tk.END, result if result is not None else "Failed")
        except Exception as e: messagebox.showerror("错误", str(e))

    def on_decrypt_text():
        content = text_input.get("1.0", tk.END).strip()
        cfg = entry_config.get().strip()
        if not content: return messagebox.showwarning("提示", "请输入内容")
        try:
            result = tool.decrypt(content, cfg)
            text_output.delete("1.0", tk.END)
            if result is None: text_output.insert(tk.END, "Failed")
            else: 
                # 尝试格式化 JSON
                if isinstance(result, str):
                    try:
                        json_obj = json.loads(result)
                        formatted_json = json.dumps(json_obj, indent=4, ensure_ascii=False)
                        text_output.insert(tk.END, formatted_json)
                    except:
                        text_output.insert(tk.END, result)
                else:
                    text_output.insert(tk.END, f"[Binary Data]: {result}")
        except Exception as e: messagebox.showerror("错误", str(e))

    def clear_all_text():
        clear_input()
        clear_output()

    create_btn(frame_btn_center_text, "加密 (Encrypt)", on_encrypt_text, COLOR_BTN_ENC, COLOR_BTN_ENC_HOVER).pack(side=tk.LEFT, padx=10)
    create_btn(frame_btn_center_text, "解密 (Decrypt)", on_decrypt_text, COLOR_BTN_DEC, COLOR_BTN_DEC_HOVER).pack(side=tk.LEFT, padx=10)
    create_btn(frame_btn_center_text, "全部清空", clear_all_text, COLOR_BTN_CLEAR, COLOR_BTN_CLEAR_HOVER, COLOR_BTN_CLEAR_TEXT).pack(side=tk.LEFT, padx=10)


    # === Tab 2: 流文件处理 ===
    tab_file = tk.Frame(notebook, bg=COLOR_BG)
    notebook.add(tab_file, text="流文件处理 (File)")

    frame_file_area = tk.Frame(tab_file, bg=COLOR_FRAME_BG, padx=20, pady=20)
    frame_file_area.pack(fill=tk.BOTH, expand=True, pady=20, padx=20)
    frame_file_area.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

    # 文件选择
    tk.Label(frame_file_area, text="选择文件 (Select File):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W)
    
    frame_file_sel = tk.Frame(frame_file_area, bg=COLOR_FRAME_BG)
    frame_file_sel.pack(fill=tk.X, pady=(5, 20))
    
    entry_filepath = tk.Entry(frame_file_sel, font=normal_font, bg="#FAFAFA", relief="flat", highlightthickness=1, highlightbackground=COLOR_BORDER)
    entry_filepath.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

    def select_file():
        path = filedialog.askopenfilename()
        if path:
            entry_filepath.delete(0, tk.END)
            entry_filepath.insert(0, path)
    
    tk.Button(frame_file_sel, text="浏览...", command=select_file, font=normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT, relief="flat", padx=10).pack(side=tk.LEFT, padx=(10, 0))

    # 状态显示
    lbl_status = tk.Label(frame_file_area, text="Ready", font=normal_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT_LIGHT)
    lbl_status.pack(pady=10)

    # 文件操作按钮 (统一布局)
    frame_btns_file = tk.Frame(frame_file_area, bg=COLOR_FRAME_BG)
    frame_btns_file.pack(pady=10)
    frame_btn_center_file = tk.Frame(frame_btns_file, bg=COLOR_FRAME_BG) # 居中容器
    frame_btn_center_file.pack()

    # 文件预览区域
    frame_preview = tk.Frame(tab_file, bg=COLOR_FRAME_BG, padx=15, pady=10)
    frame_preview.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
    frame_preview.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)
    
    tk.Label(frame_preview, text="处理结果预览 (Preview):", font=title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W, pady=(0, 5))
    text_preview = scrolledtext.ScrolledText(frame_preview, height=10, font=normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
    text_preview.pack(fill=tk.BOTH, expand=True)
    text_preview.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)

    def process_file_action(is_encrypt):
        in_path = entry_filepath.get().strip()
        cfg = entry_config.get().strip()
        if not in_path or not os.path.exists(in_path):
            messagebox.showwarning("提示", "请选择有效的文件")
            return
        
        dir_name, file_name = os.path.split(in_path)
        name, ext = os.path.splitext(file_name)
        suffix = "_encrypted" if is_encrypt else "_decrypted"
        out_path = os.path.join(dir_name, f"{name}{suffix}{ext}")
        
        out_path = filedialog.asksaveasfilename(initialfile=f"{name}{suffix}{ext}", initialdir=dir_name)
        if not out_path: return

        lbl_status.config(text="Processing...", fg=COLOR_BTN_ENC_HOVER if is_encrypt else COLOR_BTN_DEC)
        window.update()

        success, msg, preview_content = tool.process_file(in_path, out_path, cfg, is_encrypt)
        
        if success:
            lbl_status.config(text=msg, fg="green")
            messagebox.showinfo("成功", msg)
            
            # 显示预览 (无论是加密还是解密)
            text_preview.delete("1.0", tk.END)
            if preview_content:
                text_preview.insert(tk.END, preview_content)
            else:
                text_preview.insert(tk.END, "[Binary Data - Cannot Preview]")
        else:
            lbl_status.config(text="Failed", fg="red")
            messagebox.showerror("失败", msg)

    # 使用相同的 create_btn 函数和布局逻辑
    create_btn(frame_btn_center_file, "加密文件", lambda: process_file_action(True), COLOR_BTN_ENC, COLOR_BTN_ENC_HOVER).pack(side=tk.LEFT, padx=10)
    create_btn(frame_btn_center_file, "解密文件", lambda: process_file_action(False), COLOR_BTN_DEC, COLOR_BTN_DEC_HOVER).pack(side=tk.LEFT, padx=10)

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
