# -*- coding: utf-8 -*-

import os
import json
import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog, ttk
from tkinter import font as tkfont

from .config import *

class CryptoGUI:
    def __init__(self, tool, root):
        self.tool = tool
        self.window = root
        self.window.title("Ad Tools Crypto")
        self.window.geometry("900x750")
        self.window.configure(bg=COLOR_BG)

        self._init_fonts()
        self._init_ui()

    def _init_fonts(self):
        self.title_font = tkfont.Font(family=FONT_FAMILY, size=11, weight="bold")
        self.normal_font = tkfont.Font(family=FONT_FAMILY, size=10)
        self.code_font = tkfont.Font(family=FONT_CODE, size=10)

    def _init_ui(self):
        # --- 顶部配置区域 ---
        self._create_top_config_area()

        # --- 选项卡区域 ---
        self._create_notebook()

    def _create_top_config_area(self):
        frame_top = tk.Frame(self.window, bg=COLOR_FRAME_BG, padx=20, pady=15)
        frame_top.pack(fill=tk.X, padx=15, pady=(15, 10))
        frame_top.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

        tk.Label(frame_top, text="加密流程配置 (Config):", font=self.title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W)
        tk.Label(frame_top, text="101=GZIP, 1001=AES, -999=Base64 (逗号分隔)", font=self.normal_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT_LIGHT).pack(anchor=tk.W, pady=(2, 5))

        self.entry_config = tk.Entry(frame_top, font=self.code_font, bg="#FAFAFA", fg=COLOR_TEXT, relief="flat", highlightthickness=1, highlightbackground=COLOR_BORDER)
        # 默认初始值 (Tab 0 - Text)
        self.entry_config.insert(0, CONFIG_TEXT_DEFAULT)
        self.entry_config.pack(fill=tk.X, ipady=5)

    def _create_notebook(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TNotebook", background=COLOR_BG, borderwidth=0)
        style.configure("TNotebook.Tab", background="#E0E0E0", foreground=COLOR_TEXT, padding=[15, 5], font=self.normal_font)
        style.map("TNotebook.Tab", background=[("selected", COLOR_FRAME_BG)], foreground=[("selected", COLOR_BTN_ENC)])

        self.notebook = ttk.Notebook(self.window)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=15, pady=5)

        # 状态管理：记住每个Tab的配置
        # Index 0: Text Tab, Index 1: File Tab
        self.config_store = [CONFIG_TEXT_DEFAULT, CONFIG_FILE_DEFAULT]
        self.current_tab_index = 0

        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_change)

        # 创建两个 Tab
        self._create_text_tab()
        self._create_file_tab()

    def _on_tab_change(self, event):
        """切换Tab时自动保存和加载配置"""
        selected_tab_id = self.notebook.index(self.notebook.select())
        
        # 保存旧Tab的配置
        self.config_store[self.current_tab_index] = self.entry_config.get()

        # 加载新Tab的配置
        self.entry_config.delete(0, tk.END)
        self.entry_config.insert(0, self.config_store[selected_tab_id])

        # 更新当前Tab索引
        self.current_tab_index = selected_tab_id

    # ================= Tab 1: 文本处理 =================
    def _create_text_tab(self):
        tab_text = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(tab_text, text="文本处理 (Text)")

        # 输入区
        frame_input = tk.Frame(tab_text, bg=COLOR_FRAME_BG, padx=15, pady=10)
        frame_input.pack(fill=tk.BOTH, expand=True, pady=(10, 10))
        frame_input.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

        frame_input_header = tk.Frame(frame_input, bg=COLOR_FRAME_BG)
        frame_input_header.pack(fill=tk.X, pady=(0, 5))
        tk.Label(frame_input_header, text="输入内容 (Input):", font=self.title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(side=tk.LEFT)
        
        self.text_input = scrolledtext.ScrolledText(frame_input, height=8, font=self.normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
        self.text_input.pack(fill=tk.BOTH, expand=True)
        self.text_input.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)
        
        tk.Button(frame_input_header, text="清空", command=lambda: self.text_input.delete("1.0", tk.END), 
                  font=self.normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT, relief="flat", cursor="hand2").pack(side=tk.RIGHT)

        # 按钮区
        frame_btns = tk.Frame(tab_text, bg=COLOR_BG)
        frame_btns.pack(fill=tk.X, pady=5)
        frame_center = tk.Frame(frame_btns, bg=COLOR_BG)
        frame_center.pack()

        self._create_btn(frame_center, "加密 (Encrypt)", self._on_encrypt_text, COLOR_BTN_ENC, COLOR_BTN_ENC_HOVER).pack(side=tk.LEFT, padx=10)
        self._create_btn(frame_center, "解密 (Decrypt)", self._on_decrypt_text, COLOR_BTN_DEC, COLOR_BTN_DEC_HOVER).pack(side=tk.LEFT, padx=10)
        self._create_btn(frame_center, "全部清空", self._clear_all_text, COLOR_BTN_CLEAR, COLOR_BTN_CLEAR_HOVER, COLOR_BTN_CLEAR_TEXT).pack(side=tk.LEFT, padx=10)

        # 输出区
        frame_output = tk.Frame(tab_text, bg=COLOR_FRAME_BG, padx=15, pady=10)
        frame_output.pack(fill=tk.BOTH, expand=True, pady=(10, 15))
        frame_output.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

        frame_out_header = tk.Frame(frame_output, bg=COLOR_FRAME_BG)
        frame_out_header.pack(fill=tk.X, pady=(0, 5))
        tk.Label(frame_out_header, text="输出结果 (Output):", font=self.title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(side=tk.LEFT)
        
        self.text_output = scrolledtext.ScrolledText(frame_output, height=8, font=self.normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
        self.text_output.pack(fill=tk.BOTH, expand=True)
        self.text_output.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)

        tk.Button(frame_out_header, text="清空", command=lambda: self.text_output.delete("1.0", tk.END), 
                  font=self.normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT, relief="flat", cursor="hand2").pack(side=tk.RIGHT)

    def _on_encrypt_text(self):
        content = self.text_input.get("1.0", tk.END).strip()
        cfg = self.entry_config.get().strip()
        if not content: return messagebox.showwarning("提示", "请输入内容")
        try:
            result = self.tool.encrypt(content, cfg)
            self.text_output.delete("1.0", tk.END)
            self.text_output.insert(tk.END, result if result is not None else "Failed")
        except Exception as e: messagebox.showerror("错误", str(e))

    def _on_decrypt_text(self):
        content = self.text_input.get("1.0", tk.END).strip()
        cfg = self.entry_config.get().strip()
        if not content: return messagebox.showwarning("提示", "请输入内容")
        try:
            result = self.tool.decrypt(content, cfg)
            self.text_output.delete("1.0", tk.END)
            if result is None: self.text_output.insert(tk.END, "Failed")
            else: 
                if isinstance(result, str):
                    try:
                        json_obj = json.loads(result)
                        formatted_json = json.dumps(json_obj, indent=4, ensure_ascii=False)
                        self.text_output.insert(tk.END, formatted_json)
                    except:
                        self.text_output.insert(tk.END, result)
                else:
                    self.text_output.insert(tk.END, f"[Binary Data]: {result}")
        except Exception as e: messagebox.showerror("错误", str(e))

    def _clear_all_text(self):
        self.text_input.delete("1.0", tk.END)
        self.text_output.delete("1.0", tk.END)

    # ================= Tab 2: 文件处理 =================
    def _create_file_tab(self):
        tab_file = tk.Frame(self.notebook, bg=COLOR_BG)
        self.notebook.add(tab_file, text="文件处理 (File)")

        frame_area = tk.Frame(tab_file, bg=COLOR_FRAME_BG, padx=20, pady=20)
        frame_area.pack(fill=tk.BOTH, expand=True, pady=20, padx=20)
        frame_area.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)

        # 文件选择
        tk.Label(frame_area, text="选择文件 (Select File):", font=self.title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W)
        
        frame_sel = tk.Frame(frame_area, bg=COLOR_FRAME_BG)
        frame_sel.pack(fill=tk.X, pady=(5, 20))
        
        self.entry_filepath = tk.Entry(frame_sel, font=self.normal_font, bg="#FAFAFA", relief="flat", highlightthickness=1, highlightbackground=COLOR_BORDER)
        self.entry_filepath.pack(side=tk.LEFT, fill=tk.X, expand=True, ipady=5)

        tk.Button(frame_sel, text="浏览...", command=self._select_file, font=self.normal_font, bg=COLOR_BTN_CLEAR, fg=COLOR_BTN_CLEAR_TEXT, relief="flat", padx=10).pack(side=tk.LEFT, padx=(10, 0))

        # 状态
        self.lbl_status = tk.Label(frame_area, text="Ready", font=self.normal_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT_LIGHT)
        self.lbl_status.pack(pady=10)

        # 按钮
        frame_btns = tk.Frame(frame_area, bg=COLOR_FRAME_BG)
        frame_btns.pack(pady=10)
        frame_center = tk.Frame(frame_btns, bg=COLOR_FRAME_BG)
        frame_center.pack()

        self._create_btn(frame_center, "加密文件", lambda: self._process_file_action(True), COLOR_BTN_ENC, COLOR_BTN_ENC_HOVER).pack(side=tk.LEFT, padx=10)
        self._create_btn(frame_center, "解密文件", lambda: self._process_file_action(False), COLOR_BTN_DEC, COLOR_BTN_DEC_HOVER).pack(side=tk.LEFT, padx=10)

        # 预览区
        frame_preview = tk.Frame(tab_file, bg=COLOR_FRAME_BG, padx=15, pady=10)
        frame_preview.pack(fill=tk.BOTH, expand=True, padx=20, pady=(0, 20))
        frame_preview.configure(highlightbackground=COLOR_BORDER, highlightthickness=1)
        
        tk.Label(frame_preview, text="处理结果预览 (Preview):", font=self.title_font, bg=COLOR_FRAME_BG, fg=COLOR_TEXT).pack(anchor=tk.W, pady=(0, 5))
        self.text_preview = scrolledtext.ScrolledText(frame_preview, height=10, font=self.normal_font, bg="#FAFAFA", relief="flat", padx=5, pady=5)
        self.text_preview.pack(fill=tk.BOTH, expand=True)
        self.text_preview.configure(highlightthickness=1, highlightbackground=COLOR_BORDER)

    def _select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.entry_filepath.delete(0, tk.END)
            self.entry_filepath.insert(0, path)

    def _process_file_action(self, is_encrypt):
        in_path = self.entry_filepath.get().strip()
        cfg = self.entry_config.get().strip()
        if not in_path or not os.path.exists(in_path):
            messagebox.showwarning("提示", "请选择有效的文件")
            return
        
        dir_name, file_name = os.path.split(in_path)
        name, ext = os.path.splitext(file_name)
        suffix = "_encrypted" if is_encrypt else "_decrypted"
        
        out_path = filedialog.asksaveasfilename(initialfile=f"{name}{suffix}{ext}", initialdir=dir_name)
        if not out_path: return

        self.lbl_status.config(text="Processing...", fg=COLOR_BTN_ENC_HOVER if is_encrypt else COLOR_BTN_DEC)
        self.window.update()

        success, msg, preview_content = self.tool.process_file(in_path, out_path, cfg, is_encrypt)
        
        if success:
            self.lbl_status.config(text=msg, fg="green")
            messagebox.showinfo("成功", msg)
            
            self.text_preview.delete("1.0", tk.END)
            if preview_content:
                self.text_preview.insert(tk.END, preview_content)
            else:
                self.text_preview.insert(tk.END, "[Binary Data - Cannot Preview]")
        else:
            self.lbl_status.config(text="Failed", fg="red")
            messagebox.showerror("失败", msg)

    def _create_btn(self, parent, text, command, bg_color, hover_color, text_color="white"):
        btn = tk.Button(parent, text=text, command=command, font=self.title_font, bg=bg_color, fg=text_color, activebackground=hover_color, activeforeground=text_color, relief="flat", cursor="hand2", width=15, pady=6)
        return btn
