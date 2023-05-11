import pickle
import pathlib

package_file = open("/tmp/Packages", 'r')

package_to_source = {}
source_to_package = {}

package_name_to_source = {}
source_to_package_name = {}

cur_source = ''

for line in package_file:
    if line.startswith('Package'):
        # new package starts, so reset some vars
        package = line.strip().split(':', 1)[1].strip()
        cur_source = ''
    elif line.startswith('Source'):
        cur_source = line.strip().split(':', 1)[1].strip()
    elif line.startswith('Filename'):
        filename = pathlib.Path(line.strip().split(':', 1)[1].strip()).name
        if cur_source == '':
            package_to_source[filename] = package
            if package not in source_to_package:
                source_to_package[package] = []
            source_to_package[package].append(filename)

            package_name_to_source[package] = package
            if package not in source_to_package_name:
                source_to_package_name[package] = []
            source_to_package_name[package].append(package)
        else:
            package_to_source[filename] = cur_source
            if cur_source not in source_to_package:
                source_to_package[cur_source] = []
            source_to_package[cur_source].append(filename)

            package_name_to_source[package] = cur_source
            if cur_source not in source_to_package_name:
                source_to_package_name[cur_source] = []
            source_to_package_name[cur_source].append(package)

pickle_file = open('debian_packages.pickle', 'wb')
pickle.dump((package_to_source, source_to_package, package_name_to_source, source_to_package_name), pickle_file)
pickle_file.close()
