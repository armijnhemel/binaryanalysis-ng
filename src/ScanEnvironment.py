class ScanEnvironment:
    tlshlabelsignore = set([
        'compressed', 'graphics', 'audio', 'archive',
        'filesystem', 'srec', 'ihex', 'padding',
        'database'])

    def __init__(self, maxbytes, readsize, createbytecounter,
            tlshmaximum, synthesizedminimum, logging, paddingname):
            self.maxbytes = maxbytes
            self.readsize = readsize
            self.createbytecounter = createbytecounter
            self.tlshmaximum = tlshmaximum
            self.synthesizedminimum = synthesizedminimum
            self.logging = logging
            self.paddingname = paddingname

    def get_readsize(self):
        return self.readsize

    def get_createbytecounter(self):
        return self.createbytecounter

    def get_tlsmaximum(self):
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


