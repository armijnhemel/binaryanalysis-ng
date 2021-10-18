import collections

class QueueEmptyError(Exception):
    pass

class MockQueue:
    Empty = QueueEmptyError
    def __init__(self):
        self.queue = collections.deque() #[]
        self._history = []
    def get(self, timeout=0):
        try:
            item = self.queue.popleft()
            self.history.append(-1)
            return item
        except IndexError:
            raise QueueEmptyError()
    def put(self, job):
        self._history.append(job)
        self.queue.append(job)
    def task_done(self):
        pass
    @property
    def history(self):
        return self._history

class MockLock:
    def acquire(self): pass
    def release(self): pass


