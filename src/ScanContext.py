
class ScanContext:
    def __init__(self, unpackdirectory, temporarydirectory):
        """creates a scan context. This context contains:
        - unpackdirectory: absolute path the unpacking directory
        - temporarydirectory: absolute path of the temporary directory
        """
        # scanfilequeue cannot be an object member
        # perhaps as a class method?
        self.unpackdirectory = unpackdirectory
        self.temporarydirectory = temporarydirectory
        self.lenunpackdirectory = len(str(self.unpackdirectory))+1
        # scanenvironment
        # scanfilequeue
    def get_relative_path(self,fn):
        """gets the path relative to the unpackdirectory."""
        return fn[self.lenunpackdirectory:]
