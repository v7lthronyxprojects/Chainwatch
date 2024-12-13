from PyQt5.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QDialog,
    QLabel, QPushButton, QTextEdit, QLineEdit, QMessageBox, QTabWidget, QSizePolicy, QScrollArea, QShortcut
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon, QFontDatabase, QKeySequence
from typing import List, Any

from gui.worker import Worker
from analyzer.chain_watch_analyzer import CONFIG, FRAUD_PROBABILITY_THRESHOLD

class ResultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Analysis Results")
        self.setMinimumSize(800, 600)
        self.setup_ui()

    def setup_ui(self):
        layout = QVBoxLayout()
        
        self.result_text = QTextEdit()
        self.result_text.setReadOnly(True)
        
        self.plot_area = QScrollArea()
        self.plot_widget = QWidget()
        self.plot_layout = QVBoxLayout()
        self.plot_widget.setLayout(self.plot_layout)
        self.plot_area.setWidget(self.plot_widget)
        self.plot_area.setWidgetResizable(True)
        
        layout.addWidget(self.result_text)
        layout.addWidget(self.plot_area)
        
        close_button = QPushButton("Close")
        close_button.clicked.connect(self.close)
        layout.addWidget(close_button)
        
        self.setLayout(layout)
        
        self.setStyleSheet("""
            QDialog {
                background-color: #000000;
            }
            QTextEdit {
                background-color: #111111;
                border: 2px solid #222222;
                border-radius: 8px;
                padding: 12px;
                color: #00ff9d;
                font-family: 'Lalezar';
                margin: 8px;
                selection-background-color: #00ff9d;
                selection-color: #000000;
            }
            QScrollArea {
                border: 2px solid #222222;
                border-radius: 8px;
                background-color: transparent;
            }
            QPushButton {
                background-color: #111111;
                border: 2px solid #00ff9d;
                border-radius: 12px;
                padding: 15px 30px;
                color: #00ff9d;
                font-weight: bold;
                min-width: 200px;
                margin: 10px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #000000;
            }
        """)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.translations = {
            'en': {
                'window_title': 'ChainWatch Analyzer',
                'brand_text': 'v7lthronyx\nchainwatch',
                'input_placeholder': 'Enter wallet addresses separated by commas...',
                'analyze_button': 'ANALYZE TRANSACTIONS',
                'language_button': 'Switch to Persian / تغییر به فارسی',
                'logs_tab': 'Logs',
                'results_tab': 'Results',
                'logs_label': 'Logs:',
                'results_label': 'Results:',
                'charts_label': 'Charts:',
                'warning_title': 'Warning',
                'warning_message': 'Please enter at least one address',
                'error_title': 'Error',
                'error_message': 'An error occurred: {}',
                'completion_title': 'Analysis Complete',
                'analysis_complete': 'Analysis has been completed successfully.'
            },
            'fa': {
                'window_title': 'تحلیلگر ChainWatch',
                'brand_text': 'v7lthronyx\nchainwatch',
                'input_placeholder': 'آدرس‌های کیف پول را با کاما وارد کنید...',
                'analyze_button': 'تحلیل تراکنش‌ها',
                'language_button': 'Switch to English / تغییر به انگلیسی',
                'logs_tab': 'لاگ‌ها',
                'results_tab': 'نتایج',
                'logs_label': 'لاگ‌ها:',
                'results_label': 'نتایج:',
                'charts_label': 'نمودارها:',
                'warning_title': 'هشدار',
                'warning_message': 'لطفاً حداقل یک آدرس وارد کنید',
                'error_title': 'خطا',
                'error_message': 'خطایی رخ داد: {}',
                'completion_title': 'تحلیل تکمیل شد',
                'analysis_complete': 'تحلیل با موفقیت به پایان رسید.'
            }
        }
        self.language = "en"
        self.load_fonts()
        self.setWindowTitle(self.translations[self.language]['window_title'])
        self.setGeometry(100, 100, 1200, 800)
        self.setWindowIcon(QIcon("assets/logo.webp"))
        self.result_dialog = None
        self.initUI()

    def load_fonts(self):
        font_id = QFontDatabase.addApplicationFont("assets/fonts/Lalezar-Regular.ttf")
        if (font_id != -1):
            font_family = QFontDatabase.applicationFontFamilies(font_id)[0]
            self.main_font = QFont(font_family, 12)
        else:
            self.main_font = QFont('Courier', 12)
        self.setFont(self.main_font)

    def initUI(self):
        self.set_dark_theme()

        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)
        main_layout.setAlignment(Qt.AlignCenter)

        brand_layout = QHBoxLayout()
        brand_layout.setAlignment(Qt.AlignCenter)
        
        brand_label = QLabel(self.translations[self.language]['brand_text'])
        brand_label.setObjectName("brandLabel")
        brand_label.setStyleSheet("""
            QLabel#brandLabel {
                color: #00ff9d;
                font-size: 32px;
                font-weight: bold;
                font-family: 'Lalezar';
                padding: 25px;
                border: 3px solid #00ff9d;
                border-radius: 15px;
                background-color: #1a1a1a;
                text-transform: uppercase;
                letter-spacing: 2px;
            }
        """)
        brand_layout.addWidget(brand_label)
        main_layout.addLayout(brand_layout)

        brand_label.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        brand_label.setMinimumHeight(100)
        
        input_layout = QVBoxLayout()
        input_layout.setAlignment(Qt.AlignCenter)
        input_layout.setSpacing(15)

        self.address_input = QLineEdit()
        self.address_input.setPlaceholderText(self.translations[self.language]['input_placeholder'])
        input_layout.addWidget(self.address_input)

        input_layout.setSpacing(15)
        self.address_input.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.address_input.setMinimumWidth(400)

        analyze_button = QPushButton(self.translations[self.language]['analyze_button'])
        analyze_button.clicked.connect(self.start_analysis)
        input_layout.addWidget(analyze_button)

        analyze_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.language_button = QPushButton(self.translations[self.language]['language_button'])
        self.language_button.clicked.connect(self.toggle_language)
        input_layout.addWidget(self.language_button)
        self.language_button.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        main_layout.addLayout(input_layout)

        log_container = QWidget()
        log_container.setObjectName("logContainer")
        log_container.setStyleSheet("""
            QWidget#logContainer {
                background-color: #1a1a1a;
                border: 2px solid #222222;
                border-radius: 12px;
                padding: 15px;
            }
        """)
        log_layout = QVBoxLayout(log_container)
        
        log_header = QLabel("🔍 Analysis Logs")
        log_header.setStyleSheet("""
            QLabel {
                color: #00ff9d;
                font-size: 18px;
                font-weight: bold;
                padding: 10px;
                background-color: #111111;
                border-radius: 6px;
                border: 1px solid #00ff9d;
            }
        """)
        log_layout.addWidget(log_header)
        
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        self.log_text.setStyleSheet("""
            QTextEdit {
                background-color: #111111;
                border: none;
                border-radius: 8px;
                padding: 15px;
                color: #00ff9d;
                font-family: 'Lalezar';
                font-size: 14px;
                line-height: 1.5;
            }
            QScrollBar:vertical {
                background: #1a1a1a;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #00ff9d;
                border-radius: 6px;
                min-height: 30px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
        """)
        log_layout.addWidget(self.log_text)
        
        self.progress_label = QLabel("⏳ Waiting for analysis...")
        self.progress_label.setStyleSheet("""
            QLabel {
                color: #FFDC00;
                font-size: 14px;
                padding: 5px;
                font-style: italic;
            }
        """)
        log_layout.addWidget(self.progress_label)
        
        main_layout.addWidget(log_container)

        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMinimumSize(800, 600)

        self.setStyleSheet(self.styleSheet() + """
            QWidget {
                min-width: 50px;
                min-height: 30px;
            }
            QLineEdit {
                min-width: 300px;
            }
            QPushButton {
                min-width: 150px;
            }
            QTextEdit {
                min-height: 150px;
            }
            QScrollArea {
                min-height: 200px;
            }
        """)

        self.address_input.keyPressEvent = self.handle_input_keypress
        
        self.address_input.setTabOrder(self.address_input, analyze_button)
        analyze_button.setTabOrder(analyze_button, self.language_button)
        
        self.analyze_shortcut = QShortcut(QKeySequence("Ctrl+Return"), self)
        self.analyze_shortcut.activated.connect(self.start_analysis)
        
        self.language_shortcut = QShortcut(QKeySequence("Ctrl+L"), self)
        self.language_shortcut.activated.connect(self.toggle_language)

    def handle_input_keypress(self, event):
        if event.key() == Qt.Key_Return or event.key() == Qt.Key_Enter:
            self.start_analysis()
        else:
            QLineEdit.keyPressEvent(self.address_input, event)

    def keyPressEvent(self, event):
        if event.key() == Qt.Key_Escape:
            if self.result_dialog and self.result_dialog.isVisible():
                self.result_dialog.close()
            else:
                self.close()
        super().keyPressEvent(event)

    def set_dark_theme(self):
        self.setStyleSheet("""
            QMainWindow {
                background-color: #000000;
            }
            QWidget {
                background-color: #0a0a0a;
                color: #00ff9d;
                font-family: 'Lalezar';
            }
            QPushButton {
                background-color: #111111;
                border: 2px solid #00ff9d;
                border-radius: 12px;
                padding: 15px 30px;
                color: #00ff9d;
                font-weight: bold;
                min-width: 200px;
                margin: 10px;
                font-size: 14px;
                text-align: center;
                text-transform: uppercase;
                letter-spacing: 1.5px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #000000;
                border-color: #00ff9d;
            }
            QPushButton:pressed {
                background-color: #00cc7e;
                border-color: #00cc7e;
                padding: 17px 30px 13px 30px;
            }
            QLineEdit {
                background-color: #111111;
                border: 2px solid #222222;
                border-radius: 12px;
                padding: 15px 20px;
                color: #00ff9d;
                font-size: 16px;
                min-width: 400px;
                margin: 10px;
                text-align: center;
                letter-spacing: 1px;
            }
            QLineEdit:focus {
                border-color: #00ff9d;
                background-color: #151515;
            }
            QLineEdit:hover {
                border-color: #00ff9d;
                background-color: #131313;
            }
            QTextEdit {
                background-color: #111111;
                border: 2px solid #222222;
                border-radius: 8px;
                padding: 12px;
                color: #00ff9d;
                font-family: 'Lalezar';
                margin: 8px;
                selection-background-color: #00ff9d;
                selection-color: #000000;
            }
            QTabWidget::pane {
                border: 2px solid #222222;
                border-radius: 8px;
                background-color: #111111;
                top: -1px;
            }
            QTabBar::tab {
                background-color: #111111;
                color: #00ff9d;
                border: 2px solid #222222;
                border-radius: 4px;
                padding: 8px 20px;
                margin: 2px;
                font-weight: bold;
            }
            QTabBar::tab:selected {
                background-color: #00ff9d;
                color: #000000;
                border-color: #00ff9d;
            }
            QTabBar::tab:hover:!selected {
                background-color: #151515;
                border-color: #00ff9d;
            }
            QLabel {
                color: #00ff9d;
                font-weight: bold;
                font-size: 16px;
                qproperty-alignment: AlignCenter;
            }
            QLabel#brandLabel {
                color: #00ff9d;
                font-size: 32px;
                font-weight: bold;
                font-family: 'Lalezar';
                padding: 30px;
                border: 3px solid #00ff9d;
                border-radius: 20px;
                background-color: #111111;
                text-transform: uppercase;
                letter-spacing: 3px;
                margin: 20px;
            }
            QScrollArea {
                border: 2px solid #222222;
                border-radius: 8px;
                background-color: transparent;
            }
            QScrollBar:vertical {
                border: none;
                background: #111111;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background: #00ff9d;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QScrollBar:horizontal {
                border: none;
                background: #111111;
                height: 10px;
                margin: 0px;
            }
            QScrollBar::handle:horizontal {
                background: #00ff9d;
                border-radius: 5px;
                min-width: 20px;
            }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
                width: 0px;
            }
            QMessageBox {
                background-color: #111111;
                border: 2px solid #00ff9d;
                border-radius: 8px;
            }
            QMessageBox QLabel {
                color: #00ff9d;
                min-width: 300px;
            }
            QMessageBox QPushButton {
                min-width: 120px;
                background-color: #111111;
                margin: 8px;
                padding: 12px 24px;
                border-radius: 10px;
            }
            QPlainTextEdit {
                background-color: #111111;
                color: #00ff9d;
                border: 2px solid #222222;
                border-radius: 8px;
                selection-background-color: #00ff9d;
                selection-color: #000000;
            }
        """)

    def start_analysis(self):
        user_input = self.address_input.text()
        if not user_input:
            QMessageBox.warning(
                self, 
                self.translations[self.language]['warning_title'],
                self.translations[self.language]['warning_message']
            )
            return

        self.log_text.clear()
        self.progress_label.setText("🔄 Starting analysis...")
        self.progress_label.setStyleSheet("color: #00FFFF; font-size: 14px; padding: 5px;")
        
        addresses = [addr.strip() for addr in user_input.split(",") if addr.strip()]
        self.worker = Worker(addresses)
        self.worker.log_signal.connect(self.update_log)
        self.worker.result_signal.connect(self.update_result)
        self.worker.start()

    def update_log(self, message: str, color: str):
        color_map = {
            "cyan": "#00FFFF",
            "red": "#FF4136", 
            "yellow": "#FFDC00",
            "green": "#2ECC40",
            "magenta": "#FF00FF"
        }

        html_message = f'''
            <div style="
                margin: 8px 0; 
                padding: 12px; 
                background-color: rgba(30, 30, 30, 0.9); 
                border-radius: 10px; 
                border-left: 4px solid {color_map.get(color, "#00FFFF")};
                font-family: 'Lalezar';
                box-shadow: 0 2px 4px rgba(0,0,0,0.2);
                animation: fadeIn 0.3s ease-in;
            ">
                <span style="
                    color: {color_map.get(color, "#00FFFF")}; 
                    font-size: 14px;
                    display: block;
                    line-height: 1.5;
                ">{message}</span>
            </div>
        '''
        
        self.log_text.append(html_message)
        
        status_updates = {
            "completed": ("✅ Analysis completed", "#2ECC40"),
            "error": ("❌ Analysis failed", "#FF4136"),
            "analyzing": ("⚡ Analysis in progress...", "#FFDC00"),
            "api": ("🔄 Checking APIs...", "#00FFFF"),
            "warning": ("⚠️ Warning", "#FFDC00")
        }
        
        for key, (text, style_color) in status_updates.items():
            if key in message.lower():
                self.progress_label.setText(text)
                self.progress_label.setStyleSheet(f"color: {style_color}; font-size: 14px; padding: 5px;")
                break
        
        scrollbar = self.log_text.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def update_result(self, message: str):
        if not self.result_dialog:
            self.result_dialog = ResultDialog(self)
            
        self.result_dialog.result_text.append(message)
        
        dialog_message = self.translations[self.language].get('analysis_complete', 'Analysis has been completed successfully.')
        if self.language == 'fa':
            dialog_message += '\n.برای مشاهده نتایج کامل روی دکمه نمایش نتایج کلیک کنید'
        else:
            dialog_message += '\nClick Show Results to view full details.'
            
        completion_dialog = QMessageBox(self)
        completion_dialog.setWindowTitle(self.translations[self.language].get('completion_title', 'Analysis Complete'))
        completion_dialog.setText(dialog_message)
        completion_dialog.setIcon(QMessageBox.Information)
        
        show_results_button = completion_dialog.addButton(
            "Show Results" if self.language == 'en' else "نمایش نتایج",
            QMessageBox.ActionRole
        )
        close_button = completion_dialog.addButton(QMessageBox.Close)
        
        completion_dialog.setStyleSheet("""
            QMessageBox {
                background-color: #1a1a1a;
                color: #00ff9d;
            }
            QMessageBox QLabel {
                color: #00ff9d;
                min-width: 400px;
            }
            QPushButton {
                background-color: #1a1a1a;
                border: 2px solid #00ff9d;
                border-radius: 8px;
                padding: 8px 16px;
                color: #00ff9d;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #00ff9d;
                color: #1a1a1a;
            }
        """)
        
        completion_dialog.exec_()
        
        if completion_dialog.clickedButton() == show_results_button:
            self.result_dialog.show()

    def analyze_transactions(self, addresses: str) -> List[Any]:
        pass

    def update_results(self, results):
        self.result_text.setPlainText(str(results))

    def handle_error(self, error):
        QMessageBox.warning(
            self,
            self.translations[self.language]['error_title'],
            self.translations[self.language]['error_message'].format(error)
        )

    def toggle_language(self):
        self.language = "fa" if self.language == "en" else "en"
        self.update_ui_language()
        self.address_input.setLayoutDirection(Qt.RightToLeft if self.language == 'fa' else Qt.LeftToRight)

    def update_ui_language(self):
        self.setWindowTitle(self.translations[self.language]['window_title'])
        
        self.address_input.setPlaceholderText(self.translations[self.language]['input_placeholder'])
        
        self.language_button.setText(self.translations[self.language]['language_button'])
        
        analyze_button = [btn for btn in self.findChildren(QPushButton) 
                         if btn is not self.language_button][0]
        analyze_button.setText(self.translations[self.language]['analyze_button'])
        
        tabs = self.findChildren(QTabWidget)[0]
        tabs.setTabText(0, self.translations[self.language]['logs_tab'])
        
        labels = self.findChildren(QLabel)
        for label in labels:
            if label.objectName() == "brandLabel":
                label.setText(self.translations[self.language]['brand_text'])
            elif "Logs" in label.text():
                label.setText(self.translations[self.language]['logs_label'])
