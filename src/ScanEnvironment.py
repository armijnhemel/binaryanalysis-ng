class ScanEnvironment:
    tlshlabelsignore = set([
        'compressed', 'graphics', 'audio', 'archive',
        'filesystem', 'srec', 'ihex', 'padding',
        'database'])

    def __init__(self, maxbytes, readsize, createbytecounter,
            tlshmaximum, synthesizedminimum, logging, paddingname,
            unpackdirectory, temporarydirectory, resultsdirectory,
            scanfilequeue, resultqueue,
            processlock, checksumdict,
            ):
        # TODO: init from options object
        self.maxbytes = maxbytes
        self.readsize = readsize
        self.createbytecounter = createbytecounter
        self.tlshmaximum = tlshmaximum
        self.synthesizedminimum = synthesizedminimum
        self.logging = logging
        self.paddingname = paddingname
        self.unpackdirectory = unpackdirectory
        self.temporarydirectory = temporarydirectory
        self.lenunpackdirectory = len(str(unpackdirectory))+1
        self.scanfilequeue = scanfilequeue
        self.resultqueue = resultqueue
        self.processlock = processlock
        self.checksumdict = checksumdict

    def get_readsize(self):
        return self.readsize

    def get_createbytecounter(self):
        return self.createbytecounter

    def get_tlshmaximum(self):
        return self.tlshmaximum

    def use_tlsh(self, filesize, labels):
        """check whether tlsh is useful here, based on file size and labels."""
        return (256 <= filesize <= self.tlshmaximum) and self.tlshlabelsignore.isdisjoint(labels)

    def get_synthesizedminimum(self):
        return self.synthesizedminimum

    def get_paddingname(self):
        return self.paddingname

    def get_maxbytes(self):
        return self.maxbytes

    def get_relative_path(self,fn):
        """gets the path relative to the unpackdirectory."""
        return fn[self.lenunpackdirectory:]

