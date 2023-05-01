class MockMetaDirectory:
    def __init__(self):
        self.info = {}

    @property
    def unpacked_files(self):
       return self.unpacked_relative_files | self.unpacked_absolute_files

    @property
    def unpacked_relative_files(self):
        return self.info.get('unpacked_relative_files',{})

    @property
    def unpacked_absolute_files(self):
        return self.info.get('unpacked_absolute_files',{})

 
