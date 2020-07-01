class MockDBConn:
    def commit(self):
        pass

class MockDBCursor:
    def execute(self, query, args):
        pass
    def fetchall(self):
        return []



