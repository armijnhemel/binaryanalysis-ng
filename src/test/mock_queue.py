import collections

class QueueEmptyError(Exception):
    pass

class MockQueue:
    Empty = QueueEmptyError
    def __init__(self):
        self.queue = collections.deque() #[]
    def get(self, timeout=0):
        try:
            return self.queue.popleft()
        except IndexError:
            raise QueueEmptyError()
    def put(self, job):
        self.queue.append(job)
    def task_done(self):
        pass

class MockLock:
    def acquire(self): pass
    def release(self): pass


