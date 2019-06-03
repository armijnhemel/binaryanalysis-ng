import sys
import csv
import os

rows = []

for i in range(1, len(sys.argv)):
    fn = os.path.join(sys.argv[i], 'timings.json.csv')
    reader = csv.reader(open(fn))
    rows += list(reader)[1:]

writer = csv.writer(sys.stdout)
fieldnames = ['testid', 'run', 'real', 'user', 'system', 'duration']
writer.writerows([fieldnames]+rows)
