import sys
import signal
import platform
import asyncio
from PyQt5.QtWidgets import QApplication
from gui.main_window import MainWindow
from termcolor import colored
from PyQt5.QtCore import Qt

def display_banner():
    banner = """
  
██╗   ██╗███████╗██╗  ████████╗██╗  ██╗██████╗  ██████╗ ███╗   ██╗██╗   ██╗██╗  ██╗
██║   ██║╚════██║██║  ╚══██╔══╝██║  ██║██╔══██╗██╔═══██╗████╗  ██║╚██╗ ██╔╝╚██╗██╔╝
██║   ██║    ██╔╝██║     ██║   ███████║██████╔╝██║   ██║██╔██╗ ██║ ╚████╔╝  ╚███╔╝ 
╚██╗ ██╔╝   ██╔╝ ██║     ██║   ██╔══██║██╔══██╗██║   ██║██║╚██╗██║  ╚██╔╝   ██╔██╗ 
 ╚████╔╝    ██║  ███████╗██║   ██║  ██║██║  ██║╚██████╔╝██║ ╚████║   ██║   ██╔╝ ██╗
  ╚═══╝     ╚═╝  ╚══════╝╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝
                                                                                       
    """
    print(colored(banner, "green"))
    print(colored("ChainWatch Analyzer v1.0.0", "cyan"))
    print(colored("Starting up...", "yellow"))

def main():
    display_banner()
    
    if platform.system() == 'Windows':
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
    else:
        asyncio.set_event_loop_policy(asyncio.DefaultEventLoopPolicy())
    
    QApplication.setAttribute(Qt.AA_EnableHighDpiScaling, True)
    QApplication.setAttribute(Qt.AA_UseHighDpiPixmaps, True)
    app = QApplication(sys.argv)
    
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    
    main_window = MainWindow()
    main_window.show()
    
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
