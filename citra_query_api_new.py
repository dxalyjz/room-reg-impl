import subprocess
import time
import threading
import os
import random
import urllib.request
import json
import tkinter as tk
from tkinter import ttk
from datetime import datetime

PORT_RANGE = (10020, 20000)
MAX_VALUE_ROOM_MEMBERS = 4
PID_FILE_NAME = "PID.txt"

MaxRoom = 20

REFRESH_INTERVAL = 3600

MASTERSERVER_URL = "127.0.0.1"

server_info: dict = {}
server_info_lock = threading.Lock()

_ui_schedule_refresh = None

def set_schedule_refresh(callback):
    global _ui_schedule_refresh
    _ui_schedule_refresh = callback

def trigger_ui_refresh():
    if _ui_schedule_refresh is not None:
        _ui_schedule_refresh()


def _find_available_port(port_range: tuple, used_ports: set) -> int:
    start, end = port_range
    port = random.randint(start, end)
    for _ in range(end - start + 1):
        if port not in used_ports:
            return port
        port += 1
        if port > end:
            port = start
    raise RuntimeError(f"No available port in range {start}-{end}")


def _init():
    with open(PID_FILE_NAME, "w") as f:
        f.write(str(os.getpid()))

    now = time.time()
    for i in range(1, MaxRoom + 1):
        name = str(i)
        server_info[name] = {
            "server_port": 0,
            "last_active_time": now,
        }


def _cleanup():
    with server_info_lock:
        for info in server_info.values():
            if "process" in info:
                try:
                    info["process"].kill()
                except Exception:
                    pass


def is_room_alive(server_name: str) -> bool:
    with server_info_lock:
        if server_name not in server_info or "process" not in server_info[server_name]:
            return False
        return server_info[server_name]["process"].poll() is None


def stop_instance(server_name: str):
    with server_info_lock:
        info = server_info.get(server_name)
        if not info or "process" not in info:
            return
        try:
            info["process"].kill()
            while info["process"].poll() is None:
                time.sleep(0.1)
        except Exception:
            pass
        info.pop("process", None)
        info["server_port"] = 0
    trigger_ui_refresh()


def start_instance(server_name: str) -> bool:
    with server_info_lock:
        if server_name not in server_info:
            return False
        info = server_info[server_name]
        if "process" in info and info["process"].poll() is None:
            return False

        used = set()
        for other_name, other_info in server_info.items():
            if other_name != server_name and other_info.get("server_port", 0):
                used.add(int(other_info["server_port"]))

    try:
        port = str(_find_available_port(PORT_RANGE, used))
    except RuntimeError as e:
        print(e)
        return False

    proc = run_citra_server_instance(server_name, port)

    if proc.poll() is None:
        with server_info_lock:
            server_info[server_name] = {
                "server_port": port,
                "process": proc,
                "last_active_time": time.time(),
            }
        trigger_ui_refresh()
        return True
    return False


def run_citra_server_instance(server_name: str, room_port: str):
    data_now = datetime.now().strftime('%Y-%m-%d_%H-00-00')
    cmd = [
        "--room-name", server_name,
        "--preferred-game", "MONSTER HUNTER 4G",
        "--preferred-game-id", "000400000011D700",
        "--port", str(room_port),
        "--max_members", str(MAX_VALUE_ROOM_MEMBERS),
        "--web-api-url", MASTERSERVER_URL,
        "--token", "tsaf12",
    ]
    return subprocess.Popen(["citra-room"] + cmd, creationflags=subprocess.CREATE_NO_WINDOW)


def fetch_lobby_rooms() -> dict:
    try:
        with urllib.request.urlopen(f"http://{MASTERSERVER_URL}/lobby", timeout=5) as resp:
            data = json.loads(resp.read())
            
            return {room["name"]: room for room in data.get("rooms", [])}
    except Exception as e:
        print(f"[清理] 获取房间列表失败: {e}")
        return {}


def cleanup_empty_rooms_loop():
    CHECK_INTERVAL = 5
    while True:
        time.sleep(CHECK_INTERVAL)
        try:
            rooms = fetch_lobby_rooms()
            if not rooms:
                continue

            restarted_count = 0
            now = time.time()

            for name, room in rooms.items():
                player_count = len(room.get("players", []))
                port = room.get("port", "?")

                with server_info_lock:
                    if name not in server_info:
                        continue
                    info = server_info[name]
                    if "process" not in info or info["process"].poll() is not None:
                        continue

                if player_count > 0:
                    with server_info_lock:
                        if name in server_info:
                            server_info[name]["last_active_time"] = now
                    continue

                with server_info_lock:
                    if name not in server_info:
                        continue
                    last_active = server_info[name].get("last_active_time", now)

                idle_duration = now - last_active
                if idle_duration < REFRESH_INTERVAL:
                    continue

                print(f"[清理]  房间 '{name}' (端口 {port}) 已空闲 {idle_duration:.0f} 秒, 重启并更换端口...")
                stop_instance(name)
                time.sleep(0.5)
                if start_instance(name):
                    restarted_count += 1
                    print(f"[清理]  房间 '{name}' 已重启")
                else:
                    print(f"[清理]  房间 '{name}' 重启失败")

            if restarted_count > 0:
                print(f"[清理] 本轮完成, 共重启 {restarted_count} 个房间")
                trigger_ui_refresh()
        except Exception as e:
            print(f"[清理] 出错: {e}")


class CitraManagerUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Citra Room Manager")
        self.root.geometry("600x450")
        self.root.minsize(500, 350)

        top_frame = ttk.Frame(self.root, padding=10)
        top_frame.pack(fill=tk.X)

        ttk.Label(top_frame, text="Citra Room Manager", font=("Segoe UI", 16, "bold")).pack(side=tk.LEFT)

        self.status_label = ttk.Label(top_frame, text="", font=("Segoe UI", 10))
        self.status_label.pack(side=tk.RIGHT, padx=10)

        columns = ("name", "port", "status")
        self.tree = ttk.Treeview(
            self.root,
            columns=columns,
            show="headings",
            selectmode="browse",
        )

        self.tree.heading("name", text="房间名")
        self.tree.heading("port", text="端口")
        self.tree.heading("status", text="状态")

        self.tree.column("name", width=150, anchor=tk.CENTER)
        self.tree.column("port", width=120, anchor=tk.CENTER)
        self.tree.column("status", width=150, anchor=tk.CENTER)

        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 5))
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        btn_frame = ttk.Frame(self.root, padding=10)
        btn_frame.pack(fill=tk.X)

        self.start_btn = ttk.Button(btn_frame, text="启动选中", command=self.start_selected)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(btn_frame, text="停止选中", command=self.stop_selected)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Separator(btn_frame, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=10)

        self.start_all_btn = ttk.Button(btn_frame, text="启动全部", command=self.start_all)
        self.start_all_btn.pack(side=tk.LEFT, padx=5)

        self.stop_all_btn = ttk.Button(btn_frame, text="停止全部", command=self.stop_all)
        self.stop_all_btn.pack(side=tk.LEFT, padx=5)

        self.refresh_display()

        set_schedule_refresh(lambda: self.root.after(0, self.refresh_display))

    def refresh_display(self):
        for item in self.tree.get_children():
            self.tree.delete(item)

        running = 0
        for name in sorted(server_info.keys(), key=int):
            alive = is_room_alive(name)
            with server_info_lock:
                info = server_info.get(name, {})
                port = info.get("server_port", 0)

            status = "运行中" if alive else "已停止"
            self.tree.insert("", tk.END, iid=name, values=(name, port, status))
            if alive:
                running += 1

        total = len(server_info)
        self.status_label.config(text=f"运行中: {running}/{total}")

    def get_selected_name(self):
        selected = self.tree.selection()
        if not selected:
            return None
        return selected[0]

    def start_selected(self):
        name = self.get_selected_name()
        if name is None:
            return
        threading.Thread(target=self._start_and_refresh, args=(name,), daemon=True).start()

    def stop_selected(self):
        name = self.get_selected_name()
        if name is None:
            return
        threading.Thread(target=self._stop_and_refresh, args=(name,), daemon=True).start()

    def start_all(self):
        def task():
            for name in list(server_info.keys()):
                if not is_room_alive(name):
                    start_instance(name)
            self.root.after(0, self.refresh_display)
        threading.Thread(target=task, daemon=True).start()

    def stop_all(self):
        def task():
            for name in list(server_info.keys()):
                stop_instance(name)
            self.root.after(0, self.refresh_display)
        threading.Thread(target=task, daemon=True).start()

    def _start_and_refresh(self, name):
        start_instance(name)
        self.root.after(0, self.refresh_display)

    def _stop_and_refresh(self, name):
        stop_instance(name)
        self.root.after(0, self.refresh_display)

    def _auto_refresh(self):
        self.refresh_display()
        self.root.after(5000, self._auto_refresh)

    def run(self):
        self.refresh_display()
        self._auto_refresh()
        threading.Thread(target=cleanup_empty_rooms_loop, daemon=True).start()
        self.root.mainloop()


if __name__ == '__main__':
    import atexit
    atexit.register(_cleanup)
    _init()

    ui = CitraManagerUI()
    ui.run()

    _cleanup()
