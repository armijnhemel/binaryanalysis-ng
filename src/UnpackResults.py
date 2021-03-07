
class UnpackResults:
    def __init__(self):
        self.labels = []
        self.metadata = {}
        self.unpacked_files = []
        self.length = 0
        self.offset = None
    def set_length(self, length):
        self.length = length
    def get_length(self):
        return self.length
    def get_labels(self):
        return self.labels
    def set_labels(self, labels):
        self.labels = labels
    def add_label(self, label):
        self.labels.append(label)
    def get_metadata(self):
        return self.metadata
    def set_metadata(self, metadata):
        self.metadata = metadata
    def get_unpacked_files(self):
        return self.unpacked_files
    def set_unpacked_files(self, files):
        self.unpacked_files = files
    def add_unpacked_file(self, unpacked_file):
        self.unpacked_files.append(unpacked_file)
    def get_offset(self, default):
        if self.offset is None:
            return default
        return self.offset
    def set_offset(self, offset):
        self.offset = offset

