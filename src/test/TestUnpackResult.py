import inspect

from TestUtil import *

import bangsignatures
import bangandroid
import bangmedia
import bangfilesystems
import bangunpack


def get_unpackers():
    functions = []
    for m in bangandroid, bangfilesystems, bangmedia, bangunpack:
        functions += [ (name,func) for name, func in
                inspect.getmembers(m, inspect.isfunction)
                if name.startswith('unpack') ]
    return dict(functions)

def get_unpackers_for_file(unpackername, f):
    ext = os.path.splitext(f)[1]
    try:
        yield bangsignatures.extensiontofunction[ext]
    except KeyError:
        pass

    try:
        yield bangsignatures.signaturetofunction[unpackername]
    except KeyError:
        pass
    
    for signature,prettyname in bangsignatures.signatureprettyprint.items():
        if prettyname == unpackername:
            try:
                yield bangsignatures.signaturetofunction[signature]
            except KeyError:
                pass
            try:
                yield bangsignatures.textonlyfunctions[prettyname]
            except KeyError:
                pass
    try:
        prettyname = bangsignatures.extensionprettyprint[ext]
        yield bangsignatures.textonlyfunctions[prettyname]
    except KeyError:
        pass

class TestUnpackResult(TestBase):
    def test_unpackdata_for_all_unpackers(self):
        unpackers = get_unpackers()
        for f,u in self.walk_available_files_with_unpackers():
            try:
                del unpackers[u.__name__]
            except KeyError as e:
                pass
        print("no tests for:")
        print("\n".join([u for u in unpackers]))
        # for all testdatafiles
        self.assertEqual(unpackers,{})
    def walk_available_files_with_unpackers(self):
        testfilesdir = os.path.join(self.testdata_dir,'unpackers')
        for dirpath, dirnames, filenames in os.walk(testfilesdir):
            unpackername = os.path.basename(dirpath)
            for f in filenames:
                relativename = os.path.join(dirpath,f)[len(self.testdata_dir)+1:]
                for unpacker in get_unpackers_for_file(unpackername, f):
                    yield relativename, unpacker
    def test_unpackresult_has_correct_filenames(self):
        for fn,unpacker in sorted(set(self.walk_available_files_with_unpackers())):
            print(fn,unpacker)
            self._copy_file_from_testdata(fn)
            fileresult = create_fileresult_for_path(self.unpackdir, pathlib.Path(fn))
            unpackresult = unpacker(fileresult, self.scan_environment, 0, '.')
            try:
                # all paths in unpackresults are relative to unpackdir
                for unpackedfile, unpackedlabel in unpackresult['filesandlabels']:
                    try:
                        print(self.unpackdir, "prefix of", unpackedfile)
                        self.assertNotEqual(unpackedfile[:len(self.unpackdir)], self.unpackdir)
                    except AssertionError as e:
                        print("Error for %s on %s" % (unpacker.__name__, fn))
                        print(e)
                        pass

            except KeyError as e:
                pass
            
        self.fail()
    def test_unpackers_throw_exceptions(self):
        unpackers = get_unpackers()
        # feed a zero length file
        fn = "/dev/null"
        name = "null"
        self._copy_file_from_testdata(fn,name)
        fileresult = create_fileresult_for_path(self.unpackdir, pathlib.Path(name))
        self.assertEqual(fileresult.filename,name)
        # unpackresult = unpacker(fileresult, self.scan_environment, 0, self.unpackdir)
        for unpackername in sorted(unpackers.keys()):
            unpacker = unpackers[unpackername]
            unpackresult = unpacker(fileresult, self.scan_environment, 0, self.unpackdir)

if __name__=="__main__":
    unittest.main()
