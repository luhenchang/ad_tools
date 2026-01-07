# -*- coding: utf-8 -*-

import sys
import tkinter as tk
from .core import CryptoTool
from .gui import CryptoGUI
from .config import DEFAULT_KEY, DEFAULT_IV

def main():
    # 初始化核心工具
    try:
        tool = CryptoTool(DEFAULT_KEY, DEFAULT_IV)
    except Exception as e:
        print(f"Error initializing CryptoTool: {e}")
        return

    # 启动 GUI
    root = tk.Tk()
    app = CryptoGUI(tool, root)
    root.mainloop()

if __name__ == "__main__":
    main()
