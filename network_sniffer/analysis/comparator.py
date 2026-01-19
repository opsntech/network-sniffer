"""Interface comparison analysis."""

from dataclasses import dataclass
from typing import Dict, Optional, List
from datetime import datetime

from ..models.metrics import InterfaceMetrics, ComparisonMetrics


@dataclass
class ComparisonResult:
    """Detailed comparison result between two interfaces."""
    timestamp: datetime
    interface_a: str
    interface_b: str

    # Metrics
    metrics_a: Dict
    metrics_b: Dict

    # Winners by category
    winners: Dict[str, str]

    # Overall
    overall_winner: str
    score_a: float
    score_b: float
    confidence: float  # How confident we are in the comparison

    # Recommendation
    recommendation: str


class InterfaceComparator:
    """
    Compares performance metrics between two network interfaces.
    Helps identify which connection is performing better.
    """

    def __init__(self):
        # Weights for different metrics in overall score
        self.weights = {
            "latency": 0.30,
            "jitter": 0.20,
            "packet_loss": 0.35,
            "bandwidth": 0.15,
        }

    def compare(
        self,
        interface_a: str,
        interface_b: str,
        metrics_a: InterfaceMetrics,
        metrics_b: InterfaceMetrics,
    ) -> ComparisonResult:
        """
        Compare two interfaces and determine which is performing better.
        """
        timestamp = datetime.now()

        # Extract key metrics
        ma = self._extract_metrics(metrics_a)
        mb = self._extract_metrics(metrics_b)

        # Determine winners by category
        winners = {}

        # Latency (lower is better)
        if ma["latency_ms"] < mb["latency_ms"]:
            winners["latency"] = interface_a
        elif mb["latency_ms"] < ma["latency_ms"]:
            winners["latency"] = interface_b
        else:
            winners["latency"] = "tie"

        # Jitter (lower is better)
        if ma["jitter_ms"] < mb["jitter_ms"]:
            winners["jitter"] = interface_a
        elif mb["jitter_ms"] < ma["jitter_ms"]:
            winners["jitter"] = interface_b
        else:
            winners["jitter"] = "tie"

        # Packet loss (lower is better)
        if ma["loss_percent"] < mb["loss_percent"]:
            winners["packet_loss"] = interface_a
        elif mb["loss_percent"] < ma["loss_percent"]:
            winners["packet_loss"] = interface_b
        else:
            winners["packet_loss"] = "tie"

        # Bandwidth (higher is better)
        if ma["bandwidth_mbps"] > mb["bandwidth_mbps"]:
            winners["bandwidth"] = interface_a
        elif mb["bandwidth_mbps"] > ma["bandwidth_mbps"]:
            winners["bandwidth"] = interface_b
        else:
            winners["bandwidth"] = "tie"

        # Calculate overall scores
        score_a = self._calculate_score(ma)
        score_b = self._calculate_score(mb)

        # Determine overall winner
        if score_a > score_b:
            overall_winner = interface_a
        elif score_b > score_a:
            overall_winner = interface_b
        else:
            overall_winner = "tie"

        # Calculate confidence based on data availability and difference
        confidence = self._calculate_confidence(ma, mb, score_a, score_b)

        # Generate recommendation
        recommendation = self._generate_recommendation(
            interface_a, interface_b, ma, mb, winners, overall_winner
        )

        return ComparisonResult(
            timestamp=timestamp,
            interface_a=interface_a,
            interface_b=interface_b,
            metrics_a=ma,
            metrics_b=mb,
            winners=winners,
            overall_winner=overall_winner,
            score_a=score_a,
            score_b=score_b,
            confidence=confidence,
            recommendation=recommendation,
        )

    def _extract_metrics(self, metrics: InterfaceMetrics) -> Dict:
        """Extract key metrics for comparison."""
        return {
            "latency_ms": metrics.avg_latency,
            "jitter_ms": metrics.avg_jitter,
            "loss_percent": metrics.packet_loss_rate,
            "bandwidth_mbps": metrics.bandwidth_mbps,
            "packets": metrics.total_packets,
            "retransmits": metrics.retransmissions,
            "rx_dropped": metrics.rx_dropped,
        }

    def _calculate_score(self, metrics: Dict) -> float:
        """
        Calculate overall score (0-100).
        Higher is better.
        """
        score = 100.0

        # Latency penalty (>150ms is bad)
        latency = metrics["latency_ms"]
        if latency > 0:
            latency_penalty = min(30, (latency / 150) * 30)
            score -= latency_penalty * self.weights["latency"] * 3.33

        # Jitter penalty (>30ms is bad)
        jitter = metrics["jitter_ms"]
        if jitter > 0:
            jitter_penalty = min(20, (jitter / 30) * 20)
            score -= jitter_penalty * self.weights["jitter"] * 5

        # Loss penalty (>1% is bad)
        loss = metrics["loss_percent"]
        if loss > 0:
            loss_penalty = min(35, loss * 35)
            score -= loss_penalty * self.weights["packet_loss"] * 2.86

        return max(0, score)

    def _calculate_confidence(
        self, ma: Dict, mb: Dict, score_a: float, score_b: float
    ) -> float:
        """Calculate confidence in the comparison."""
        # Base confidence on data availability
        confidence = 1.0

        # Reduce confidence if we have few packets
        min_packets = min(ma["packets"], mb["packets"])
        if min_packets < 100:
            confidence *= 0.5
        elif min_packets < 1000:
            confidence *= 0.8

        # Reduce confidence if scores are very close
        score_diff = abs(score_a - score_b)
        if score_diff < 5:
            confidence *= 0.7
        elif score_diff < 10:
            confidence *= 0.85

        return round(confidence, 2)

    def _generate_recommendation(
        self,
        interface_a: str,
        interface_b: str,
        ma: Dict,
        mb: Dict,
        winners: Dict,
        overall_winner: str,
    ) -> str:
        """Generate actionable recommendation."""
        if overall_winner == "tie":
            return (
                f"Both {interface_a} and {interface_b} show similar performance. "
                "Consider using load balancing for redundancy."
            )

        # Count wins
        wins_a = sum(1 for w in winners.values() if w == interface_a)
        wins_b = sum(1 for w in winners.values() if w == interface_b)

        loser = interface_b if overall_winner == interface_a else interface_a
        loser_metrics = mb if overall_winner == interface_a else ma

        # Identify main issues with losing interface
        issues = []
        if loser_metrics["loss_percent"] > 1:
            issues.append(f"high packet loss ({loser_metrics['loss_percent']:.2f}%)")
        if loser_metrics["latency_ms"] > 100:
            issues.append(f"high latency ({loser_metrics['latency_ms']:.1f}ms)")
        if loser_metrics["jitter_ms"] > 30:
            issues.append(f"high jitter ({loser_metrics['jitter_ms']:.1f}ms)")

        if issues:
            issue_str = ", ".join(issues)
            recommendation = (
                f"Use {overall_winner} for critical traffic. "
                f"{loser} shows {issue_str}. "
                f"Investigate {loser} for network issues."
            )
        else:
            recommendation = (
                f"{overall_winner} shows better overall performance "
                f"(won {max(wins_a, wins_b)}/4 categories). "
                f"Route critical traffic through {overall_winner}."
            )

        return recommendation

    def get_comparison_summary(self, result: ComparisonResult) -> str:
        """Get human-readable comparison summary."""
        lines = [
            f"Network Interface Comparison",
            f"=" * 50,
            f"Time: {result.timestamp.strftime('%Y-%m-%d %H:%M:%S')}",
            f"",
            f"  {result.interface_a:20} vs {result.interface_b:20}",
            f"",
            f"Latency:      {result.metrics_a['latency_ms']:8.1f} ms    {result.metrics_b['latency_ms']:8.1f} ms  -> {result.winners['latency']}",
            f"Jitter:       {result.metrics_a['jitter_ms']:8.1f} ms    {result.metrics_b['jitter_ms']:8.1f} ms  -> {result.winners['jitter']}",
            f"Packet Loss:  {result.metrics_a['loss_percent']:8.2f} %     {result.metrics_b['loss_percent']:8.2f} %   -> {result.winners['packet_loss']}",
            f"Bandwidth:    {result.metrics_a['bandwidth_mbps']:8.1f} Mbps  {result.metrics_b['bandwidth_mbps']:8.1f} Mbps -> {result.winners['bandwidth']}",
            f"",
            f"Overall Score: {result.score_a:.0f} vs {result.score_b:.0f}",
            f"Winner: {result.overall_winner} (confidence: {result.confidence*100:.0f}%)",
            f"",
            f"Recommendation:",
            f"  {result.recommendation}",
        ]
        return "\n".join(lines)
