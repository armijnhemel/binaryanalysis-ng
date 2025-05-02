import collections

# input:
# list of identifiers with per line:
#  - number how often the identifier appears in the data
#  - identifier
#
# For example:
#
#     6228 stderr
#
# How to generate the list:
#
# $ cat *.var| sort | uniq -c | sort -n > /tmp/var


linecounter = collections.Counter()

lines = []

identifier_file = open('var', 'r')
for line in identifier_file:
    lines.append(int(line.strip().split(" ", 1)[0]))

total_lines = len(lines)

linecounter.update(lines)

for i in linecounter.most_common():
    break
    print("%d: %d" % i)

for i in linecounter.most_common():
    print("%d - %f" % (i[0], i[1]/total_lines * 100))
