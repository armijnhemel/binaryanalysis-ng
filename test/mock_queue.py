import collections
import queue

class MockQueue(queue.Queue):
    def __init__(self):
        super().__init__()
        self.history = []

    def get(self, *args, **kwargs):
        self.history.append(-1)
        return super().get(timeout=0)

    def put(self, job):
        self.history.append(job)
        return super().put(job)


