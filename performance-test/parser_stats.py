import sys
from operator import itemgetter
from bang_log import BangLog

class ParserStats(BangLog):

    def handle_start(self):
        pass

    def handle_end(self):
        print(f'{"Success":8} {"Fail":8} {"Try":8} {"TimeSuccess":12} {"TimeFail":12} {"TimeAnalyse":12} {"TimeUnpack":12}  Parser')
        print(f'{"-"*8} {"-"*8} {"-"*8} {"-"*12} {"-"*12} {"-"*12} {"-"*12}  {"-"*10}')
        for k,v in sorted(self.parse_tries.items(), key=itemgetter(1), reverse=True):
            print(f'{self.parse_successes.get(k,0):8} {self.parse_fails.get(k,0):8} {v:8} {self.time_parse_success.get(k,0):12} {self.time_parse_fail.get(k,0):12} {self.time_analyse.get(k,0):12} {self.time_unpack.get(k,0):12}  {k}')



num_jobs = 10

pl = ParserStats(num_jobs)
pl.read(sys.stdin)





