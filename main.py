import os
import shutil
import hashlib
import time
import pandas as pd
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

class FileTransferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("内存卡备份工具")
        self.root.geometry("800x600")
        
        self.report_data = []
        
        # 创建界面元素
        self.create_widgets()
        
    def create_widgets(self):
        # 文件选择
        self.files_frame = ttk.LabelFrame(self.root, text="选择文件")
        self.files_frame.pack(fill="both", expand=True, padx=10, pady=5)
        
        self.files_listbox = tk.Listbox(self.files_frame, selectmode=tk.MULTIPLE)
        self.files_listbox.pack(fill="both", expand=True, padx=5, pady=5)
        
        self.btn_frame = ttk.Frame(self.files_frame)
        self.btn_frame.pack(fill="x", pady=5)
        
        self.add_files_btn = ttk.Button(self.btn_frame, text="添加文件", command=self.select_files)
        self.add_files_btn.pack(side="left", padx=5)
        
        self.add_folder_btn = ttk.Button(self.btn_frame, text="添加文件夹", command=self.select_folder)
        self.add_folder_btn.pack(side="left", padx=5)
        
        self.remove_btn = ttk.Button(self.btn_frame, text="移除选中", command=self.remove_selected)
        self.remove_btn.pack(side="right", padx=5)
        
        self.clear_btn = ttk.Button(self.btn_frame, text="清空列表", command=self.clear_files)
        self.clear_btn.pack(side="right", padx=5)
        
        # 目标路径选择
        self.dest_frame = ttk.LabelFrame(self.root, text="目标文件夹")
        self.dest_frame.pack(fill="x", padx=10, pady=5)
        
        self.dest_entry = ttk.Entry(self.dest_frame)
        self.dest_entry.pack(side="left", fill="x", expand=True, padx=5, pady=5)
        
        self.dest_btn = ttk.Button(self.dest_frame, text="选择", command=self.select_destination)
        self.dest_btn.pack(side="right", padx=5)
        
        # 进度显示
        self.progress_frame = ttk.Frame(self.root)
        self.progress_frame.pack(fill="x", padx=10, pady=5)
        
        self.progress = ttk.Progressbar(self.progress_frame, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(side="left", padx=5)
        
        self.progress_label = ttk.Label(self.progress_frame, text="0%")
        self.progress_label.pack(side="left", padx=5)
        
        self.verify_label = ttk.Label(self.progress_frame, text="未校验")
        self.verify_label.pack(side="right", padx=5)
        
        # 操作按钮
        self.btn_frame = ttk.Frame(self.root)
        self.btn_frame.pack(pady=10)
        
        self.transfer_btn = ttk.Button(self.btn_frame, text="开始传输", command=self.start_transfer)
        self.transfer_btn.pack(side="left", padx=5)
        
        self.report_btn = ttk.Button(self.btn_frame, text="查看报告", command=self.show_report)
        self.report_btn.pack(side="left", padx=5)
        
    def select_source(self):
        """选择源文件夹"""
        source_dir = filedialog.askdirectory(title="选择源文件夹")
        if source_dir:
            self.source_entry.delete(0, tk.END)
            self.source_entry.insert(0, source_dir)
            self.update_files_list()
            
    def select_files(self):
        """选择要传输的文件"""
        files = filedialog.askopenfilenames(title="选择要传输的文件")
        if files:
            for file in files:
                if file not in self.files_listbox.get(0, tk.END):
                    self.files_listbox.insert(tk.END, file)
                    
    def select_folder(self):
        """选择要传输的文件夹"""
        folder = filedialog.askdirectory(title="选择要传输的文件夹")
        if folder:
            for root, dirs, files in os.walk(folder):
                for file in files:
                    file_path = os.path.join(root, file)
                    if file_path not in self.files_listbox.get(0, tk.END):
                        self.files_listbox.insert(tk.END, file_path)
                        
    def clear_files(self):
        """清空文件列表"""
        self.files_listbox.delete(0, tk.END)
        
    def remove_selected(self):
        """移除选中的文件"""
        selected = self.files_listbox.curselection()
        for i in reversed(selected):
            self.files_listbox.delete(i)
                
    def select_destination(self):
        """选择目标文件夹"""
        dest_dir = filedialog.askdirectory(title="选择目标文件夹")
        if dest_dir:
            self.dest_entry.delete(0, tk.END)
            self.dest_entry.insert(0, dest_dir)
            
    def update_files_list(self):
        """更新文件列表"""
        self.files_listbox.delete(0, tk.END)
        source_dir = self.source_entry.get()
        if source_dir and os.path.isdir(source_dir):
            for file in os.listdir(source_dir):
                if os.path.isfile(os.path.join(source_dir, file)):
                    self.files_listbox.insert(tk.END, file)
                    
    def start_transfer(self):
        """开始传输"""
        dest_dir = self.dest_entry.get()
        files = self.files_listbox.get(0, tk.END)
        
        if not dest_dir:
            messagebox.showwarning("警告", "请选择目标文件夹")
            return
        if not files:
            messagebox.showwarning("警告", "请选择要传输的文件")
            return
            
        # 禁用按钮防止重复点击
        self.transfer_btn.config(state=tk.DISABLED)
        self.progress["value"] = 0
        self.progress["maximum"] = len(files)
        
        # 在后台线程中执行传输
        import threading
        transfer_thread = threading.Thread(
            target=self._transfer_files,
            args=(files, dest_dir),
            daemon=True
        )
        transfer_thread.start()
        
    def _transfer_files(self, files, dest_dir):
        """后台线程执行文件传输"""
        try:
            for i, file_path in enumerate(files):
                try:
                    file_name = os.path.basename(file_path)
                    dest_path = os.path.join(dest_dir, file_name)
                    
                    # 计算源文件哈希
                    src_hash = self.calculate_hash(file_path)
                    
                    # 复制文件
                    shutil.copy2(file_path, dest_path)
                    
                    # 计算目标文件哈希
                    dest_hash = self.calculate_hash(dest_path)
                    
                    # 记录传输结果
                    status = "Success" if src_hash == dest_hash else "Hash Mismatch"
                    self.report_data.append({
                        'source': file_path,
                        'destination': dest_path,
                        'status': status,
                        'source_hash': src_hash,
                        'destination_hash': dest_hash,
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
                    # 更新进度条
                    self.root.after(0, self._update_progress, i + 1)
                    time.sleep(0.1)  # 添加短暂延迟确保UI更新
                    
                except Exception as e:
                    self.report_data.append({
                        'source': file_path,
                        'destination': dest_dir,
                        'status': str(e),
                        'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
                    })
                    
            self.root.after(0, self._transfer_complete)
            
        except Exception as e:
            self.root.after(0, messagebox.showerror, "错误", f"传输过程中发生错误: {str(e)}")
            self.root.after(0, self._transfer_complete)
            
    def _update_progress(self, value):
        """更新进度条"""
        self.progress["value"] = value
        percent = int(value/self.progress['maximum']*100)
        self.progress_label.config(text=f"{percent}%")
        self.root.update_idletasks()
        if value == self.progress["maximum"]:
            self.verify_label.config(text="校验完成")
        else:
            self.verify_label.config(text="校验中...")
            
    def _transfer_complete(self):
        """传输完成处理"""
        self.generate_report()
        self.transfer_btn.config(state=tk.NORMAL)
        messagebox.showinfo("完成", "文件传输完成！")
        
    def calculate_hash(self, file_path, algorithm='sha256'):
        """计算文件哈希值"""
        hash_func = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_func.update(chunk)
        return hash_func.hexdigest()

    def generate_report(self):
        """生成传输报告"""
        df = pd.DataFrame(self.report_data)
        report_path = os.path.join(os.path.expanduser("~"), 'Desktop', 'transfer_report.csv')
        df.to_csv(report_path, index=False)
        
    def show_report(self):
        """显示传输报告"""
        if not self.report_data:
            messagebox.showinfo("报告", "还没有生成传输报告")
            return
            
        report_path = os.path.join(os.getcwd(), 'transfer_report.csv')
        if os.path.exists(report_path):
            os.startfile(report_path)
        else:
            messagebox.showwarning("警告", "找不到传输报告文件")

def main():
    root = tk.Tk()
    app = FileTransferApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
