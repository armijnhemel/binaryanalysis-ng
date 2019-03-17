import json
import copy

class JsonReporter:
    def __init__(self, reportfile):
        self.reportfile = reportfile
    def report(self,scanresult):
        # copy scanresult because json cannot serialize datetime objects by itself
        sr = copy.deepcopy(scanresult)
        sr['session']['start'] = sr['session']['start'].isoformat()
        sr['session']['stop'] = sr['session']['stop'].isoformat()
        json.dump(sr, self.reportfile)


