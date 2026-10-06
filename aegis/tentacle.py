"""Контракт щупальца. Пассивные — active=False; активные обязаны идти через scope.require_active."""
class Tentacle:
    name = "base"
    active = False
    def run(self, conn, asset):
        """Вернуть список dict: {asset_kind, asset_value, key, value, evidence}"""
        raise NotImplementedError

class Example(Tentacle):
    name = "example"
    def run(self, conn, asset):
        return []
