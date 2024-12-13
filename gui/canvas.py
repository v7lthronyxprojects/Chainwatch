from PyQt5.QtWidgets import QSizePolicy
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
import matplotlib.pyplot as plt

class MplCanvas(FigureCanvas):
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        self.fig, self.ax = plt.subplots(figsize=(width, height), dpi=dpi)
        super(MplCanvas, self).__init__(self.fig)
        
        self.setParent(parent)
        
        self.setSizePolicy(
            QSizePolicy.Expanding,
            QSizePolicy.Expanding
        )
        
        self.fig.set_tight_layout(True)
        
        self.setMinimumSize(300, 200)
    
    def resizeEvent(self, event):
        super().resizeEvent(event)
        self.fig.set_size_inches(
            event.size().width() / self.fig.get_dpi(),
            event.size().height() / self.fig.get_dpi()
        )
