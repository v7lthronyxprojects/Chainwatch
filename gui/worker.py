from PyQt5.QtCore import QThread, pyqtSignal, QEventLoop
from analyzer.chain_watch_analyzer import ChainWatchAnalyzer
import asyncio
import platform
from typing import List
import traceback

class Worker(QThread):
    log_signal = pyqtSignal(str, str)  
    result_signal = pyqtSignal(str)
    plot_signal = pyqtSignal(str, object)  
    progress_signal = pyqtSignal(int)  

    def __init__(self, addresses: List[str]):
        super().__init__()
        self.addresses = addresses
        self.analyzer = ChainWatchAnalyzer(log_callback=self.emit_log)

    def emit_log(self, message: str, color: str = "cyan"):
        self.log_signal.emit(message, color)
        QThread.msleep(1)

    def run(self):
        try:
            self.log_signal.emit("🔄 Initializing systems...", "cyan")
            
            if platform.system() == 'Windows':
                loop = asyncio.ProactorEventLoop()
            else:
                loop = asyncio.new_event_loop()
                
            asyncio.set_event_loop(loop)

            try:
                if not hasattr(self, 'analyzer') or not self.analyzer:
                    raise Exception("❌ Analyzer not properly initialized")

                if not self.addresses:
                    raise ValueError("❌ No addresses provided for analysis")

                self.log_signal.emit("🔍 Starting analysis...", "cyan")
                
                loop.run_until_complete(asyncio.wait_for(
                    self._run_analysis(),
                    timeout=300  
                ))
                
                self.log_signal.emit("✅ Analysis completed successfully", "green")
                self.result_signal.emit("Analysis completed successfully")
                
            except asyncio.TimeoutError:
                self.log_signal.emit("⚠️ Analysis timed out after 5 minutes", "red")
                self.result_signal.emit("Analysis timed out")
            except Exception as e:
                error_msg = f"❌ Error during analysis: {str(e)}\n{traceback.format_exc()}"
                self.log_signal.emit(error_msg, "red")
                self.result_signal.emit("Analysis failed")
            finally:
                loop.close()
                
        except Exception as e:
            error_msg = f"❌ Critical error: {str(e)}\n{traceback.format_exc()}"
            self.log_signal.emit(error_msg, "red")
            self.result_signal.emit("Analysis failed due to critical error")

    async def _run_analysis(self):
        """Async method to run the actual analysis."""
        try:
            api_status = await self.analyzer.verify_api_keys()
            if not any(api_status.values()):
                raise Exception("❌ No working APIs found. Please check your API keys.")
            
            await self.analyzer.execute_analysis(self.addresses)
        except Exception as e:
            self.log_signal.emit(f"❌ Analysis error: {str(e)}", "red")
            raise

    def processEvents(self):
        """Dummy method to prevent attribute errors"""
        pass

