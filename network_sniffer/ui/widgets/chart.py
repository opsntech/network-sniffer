"""Time series chart widget using Plotext for terminal-based graphs."""

from textual.widgets import Static
from typing import List, Dict, Optional
import io

try:
    import plotext as plt
    PLOTEXT_AVAILABLE = True
except ImportError:
    PLOTEXT_AVAILABLE = False


class TimeSeriesChart(Static):
    """Real-time time series chart for terminal display."""

    DEFAULT_CSS = """
    TimeSeriesChart {
        height: 100%;
        padding: 0;
        background: $surface;
    }
    """

    def __init__(
        self,
        title: str = "Chart",
        y_label: str = "Value",
        max_points: int = 60,
        **kwargs
    ):
        super().__init__(**kwargs)
        self.title = title
        self.y_label = y_label
        self.max_points = max_points
        self._data: Dict[str, List[float]] = {}
        self._colors = ["cyan", "magenta", "yellow", "green", "red"]

    def add_series(self, name: str, values: List[float]) -> None:
        """Add or update a data series."""
        self._data[name] = values[-self.max_points:]
        self.refresh()

    def clear(self) -> None:
        """Clear all data."""
        self._data.clear()
        self.refresh()

    def render(self) -> str:
        """Render the chart."""
        if not PLOTEXT_AVAILABLE:
            return "[dim]Plotext not installed. Install with: pip install plotext[/dim]"

        if not self._data:
            return f"[bold]{self.title}[/bold]\n[dim]No data yet...[/dim]"

        # Clear previous plot
        plt.clear_figure()

        # Configure plot
        plt.title(self.title)
        plt.xlabel("Time (seconds ago)")
        plt.ylabel(self.y_label)

        # Plot each series
        for i, (name, values) in enumerate(self._data.items()):
            if values:
                x = list(range(-len(values) + 1, 1))
                color = self._colors[i % len(self._colors)]
                plt.plot(x, values, label=name, color=color)

        # Configure size based on widget size
        plt.plotsize(60, 15)
        plt.theme("dark")

        # Build the plot string
        return plt.build()


class SparklineChart(Static):
    """Simple sparkline chart (no external dependencies)."""

    SPARK_CHARS = "▁▂▃▄▅▆▇█"

    DEFAULT_CSS = """
    SparklineChart {
        height: 3;
        padding: 0 1;
        background: $surface;
    }
    """

    def __init__(self, title: str = "", width: int = 50, **kwargs):
        super().__init__(**kwargs)
        self.title = title
        self.width = width
        self._values: List[float] = []
        self._color = "cyan"

    def update_values(self, values: List[float], color: str = "cyan") -> None:
        """Update sparkline values."""
        self._values = values[-self.width:]
        self._color = color
        self.refresh()

    def render(self) -> str:
        """Render the sparkline."""
        if not self._values:
            return f"{self.title}: [dim]--[/dim]"

        # Normalize values
        min_val = min(self._values) if self._values else 0
        max_val = max(self._values) if self._values else 1
        range_val = max_val - min_val if max_val != min_val else 1

        # Build sparkline
        sparkline = ""
        for v in self._values:
            normalized = (v - min_val) / range_val
            idx = int(normalized * (len(self.SPARK_CHARS) - 1))
            sparkline += self.SPARK_CHARS[idx]

        # Current value
        current = self._values[-1] if self._values else 0

        return f"{self.title}: [{self._color}]{sparkline}[/{self._color}] {current:.1f}"
