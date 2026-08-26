from .models import (
    SecurityFinding,
    ServiceResult,
    TopologyEdge,
    TopologyNode,
)


class TopologyBuilder:
    """Build a logical topology from scanner observations."""

    def build(
        self,
        host: str,
        service_results: list[ServiceResult],
        findings: list[SecurityFinding],
    ) -> dict:

        node = TopologyNode(
            id="localhost",
            type="developer_host",
            address=host,
        )

        risk_by_port = {
            finding.port: finding.risk.value
            for finding in findings
        }

        edges = []

        for result in service_results:
            if result.state.value != "OPEN":
                continue

            edge = TopologyEdge(
                source=node.id,
                destination=f"{host}:{result.port}",
                protocol=result.protocol,
                port=result.port,
                state=result.state.value,
                service=result.service,
                risk=risk_by_port.get(
                    result.port,
                    "UNASSESSED",
                ),
            )

            edges.append(edge)

        return {
            "nodes": [
                self._serialize(node)
            ],
            "edges": [
                self._serialize(edge)
                for edge in edges
            ],
        }

    @staticmethod
    def _serialize(value):
        return {
            key: (
                item.value
                if hasattr(item, "value")
                else item
            )
            for key, item in vars(value).items()
        }
