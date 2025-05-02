#!/usr/bin/env python

import sys
import matplotlib.pyplot as plt
from bang_log import BangLog


class JobPlotter(BangLog):

    def __init__(self, num_jobs):
        super().__init__(num_jobs)
        self.queue_events = []

    def handle_start(self):
        fig, self.ax = plt.subplots()
        self.ax.set_ylim(5,self.num_jobs*10+15)
        self.ax.set_xlabel('nanoseconds since start')
        self.ax.set_yticks([15+10*i for i in range(self.num_jobs)])
        self.ax.set_yticklabels([f'Process-{i+2}' for i in range(self.num_jobs)])
        self.ax.grid(True)

    def handle_end(self):
        l = list(zip(*self.queue_events))
        self.ax.plot(*l)
        plt.show()

    def handle_job_complete(self, process):
        # print(f'{process=} {self.job_start_time[process]} - {self.job_end_time[process]}')
        facecolors = ['tab:orange', 'tab:green', 'tab:red', 'tab:blue']
        self.ax.broken_barh([(self.job_start_time[process], self.job_end_time[process])],
                (15+process*10-4,8),
                facecolors=facecolors[self.completed_jobs[process] % len(facecolors)])
        
    def handle_queue_change(self, event_time):
        self.queue_events.append((event_time, self.queued_jobs))


num_jobs = 10

pl = JobPlotter(num_jobs)
pl.read(sys.stdin)


