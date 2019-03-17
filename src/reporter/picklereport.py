import pickle

class PickleReporter:
    def __init__(self, reportfile):
        self.reportfile = reportfile
    def report(self,scanresult):
        pickle.dump(scanresult, self.reportfile)

