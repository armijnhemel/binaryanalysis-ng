
class ScanContext:
    def __init__(self, unpackdirectory, temporarydirectory):
        self.unpackdirectory = unpackdirectory
        self.temporarydirectory = temporarydirectory
        self.lenunpackdirectory = len(str(self.unpackdirectory))+1
        # scanenvironment
        # scanfilequeue
    def get_relative_path(self,fn):
        return fn[self.lenunpackdirectory:]


