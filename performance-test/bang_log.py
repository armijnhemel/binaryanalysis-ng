import re

class BangLog:
    def __init__(self, num_jobs = 10):
        self.time_offset = 0
        self.num_jobs = num_jobs
        self.job_start_time = [0] * num_jobs
        self.job_end_time = [0] * num_jobs
        self.completed_jobs = [0] * num_jobs
        self.queued_jobs = 0
        self.version = (0,0,0)
        self.parse_tries = {}
        self.parse_successes = {}
        self.parse_fails = {}
        self.time_start = [0] * num_jobs
        self.time_parse_success = {}
        self.time_parse_fail = {}
        self.time_analyse = {}
        self.time_unpack = {}

    def read(self, f):
        self.handle_start()
        for l in f:
            for pattern, callback in self._callbacks:
                m = pattern.match(l)
                if m:
                    callback(self,m)
        self.handle_end()

    def version_check(self):
        return self.version < (0,0,1)

    def handle_start(self):
        '''Event handler for 'start'.'''

    def handle_end(self):
        '''Event handler for 'end'.'''

    def handle_job_complete(self, process):
        '''Event handler for 'job complete'.'''
        
    def handle_queue_change(self, event_time):
        '''Event handler for 'queue change'.'''

    def _cb_bang_version(self, m):
        self.version = tuple(map(int,m.group(1).split('.')))
        #print(f'{self.version}')
        if not self.version_check():
            raise ValueError('cannot handle version {".".join(self.version)}')

    def _cb_start_program(self, m):
        self.time_offset = int(m.group(1))

    def _cb_start_job(self, m):
        process = int(m.group(1)) - 2
        self.job_start_time[process] = int(m.group(2)) - self.time_offset
        self.job_end_time[process] = self.job_start_time[process]
        self.queued_jobs -= 1
        self.handle_queue_change(self.job_start_time[process])

    def _cb_end_job(self, m):
        process = int(m.group(1)) - 2
        self.job_end_time[process] = int(m.group(2)) - self.time_offset
        self.completed_jobs[process] += 1
        self.handle_job_complete(process)
        self.job_start_time[process] = self.job_end_time[process] = 0

    def _cb_queue_job(self, m):
        event_time = int(m.group(1)) - self.time_offset
        self.queued_jobs += 1
        self.handle_queue_change(event_time)

    def _cb_try_parse(self, m):
        process = int(m.group(1)) - 2
        parser = m.group(2)
        self.parse_tries[parser] = self.parse_tries.get(parser,0) + 1
        event_time = int(m.group(3))
        self.time_start[process] = event_time

    def _cb_success_parse(self, m):
        process = int(m.group(1)) - 2
        parser = m.group(2)
        self.parse_successes[parser] = self.parse_successes.get(parser,0) + 1
        event_time = int(m.group(3))
        self.time_parse_success.setdefault(parser,0)
        self.time_parse_success[parser] += event_time - self.time_start[process]

    def _cb_failed_parse(self, m):
        process = int(m.group(1)) - 2
        parser = m.group(2)
        self.parse_fails[parser] = self.parse_fails.get(parser,0) + 1
        event_time = int(m.group(3))
        self.time_parse_fail.setdefault(parser,0)
        self.time_parse_fail[parser] += event_time - self.time_start[process]

    def _cb_parse_analysis_start(self, m):
        process = int(m.group(1)) - 2
        event_time = int(m.group(3))
        self.time_start[process] = event_time


    def _cb_parse_unpacking_start(self, m):
        process = int(m.group(1)) - 2
        parser = m.group(2)
        event_time = int(m.group(3))
        self.time_analyse.setdefault(parser,0)
        self.time_analyse[parser] += event_time - self.time_start[process]
        self.time_start[process] = event_time

    def _cb_parse_unpacking_end(self, m):
        process = int(m.group(1)) - 2
        parser = m.group(2)
        event_time = int(m.group(3))
        self.time_unpack.setdefault(parser,0)
        self.time_unpack[parser] += event_time - self.time_start[process]


    _callbacks = [
        (re.compile(r'^\[.*\] cli:scan: BANG version (\d+)\.(\d+)\.(\d+)'), _cb_bang_version),
        (re.compile(r'^\[.*\] cli:scan: start \[(\d+)\]'), _cb_start_program),
        (re.compile(r'^\[.*Process-(\d+)\] process_jobs\[.*?\]: start job \[(\d+)\]'), _cb_start_job),
        (re.compile(r'^\[.*Process-(\d+)\] process_jobs\[.*?\]: end job \[(\d+)\]'), _cb_end_job),
        (re.compile(r'^\[.*\] .*\[.*\]: queued job \[(\d+)\]'), _cb_queue_job),
        (re.compile(r'^\[.*Process-(\d+)\] .*\[.*\]: trying parse .* with (.*) \[(.*)\]'), _cb_try_parse),
        (re.compile(r'^\[.*Process-(\d+)\] .*\[.*\]: successful parse .* with (.*) \[(.*)\]'), _cb_success_parse),
        (re.compile(r'^\[.*Process-(\d+)\] .*\[.*\]: failed parse .* with (.*) \[(.*)\]'), _cb_failed_parse),
        (re.compile(r'^\[.*Process-(\d+)\] .*\[.*\]: analyzing .* with (.*) \[(.*)\]'), _cb_parse_analysis_start),
        (re.compile(r'^\[.*Process-(\d+)\] .*\[.*\]: unpacking .* with (.*) \[(.*)\]'), _cb_parse_unpacking_start),
        (re.compile(r'^\[.*Process-(\d+)\] .*\[.*\]: unpacked .* with (.*) \[(.*)\]'), _cb_parse_unpacking_end),
    ]


