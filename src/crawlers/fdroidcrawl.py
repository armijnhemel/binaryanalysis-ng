#!/usr/bin/python3

## Binary Analysis Next Generation (BANG!)
##
## Copyright 2018 - Armijn Hemel
## Licensed under the terms of the GNU Affero General Public License version 3
## SPDX-License-Identifier: AGPL-3.0-only
##
## Crawls the release XML from F-Droid and stores files and metadata
## from the XML.
##
## The XML release format is described at:
##
## https://f-droid.org/en/docs/Build_Metadata_Reference/
##
## and in the XML file itself:
##
## https://f-droid.org/repo/index.xml

import sys, os, multiprocessing, argparse, configparser, datetime, stat
import hashlib, xml.dom.minidom, tempfile, queue

## import the requests module for downloading the XML
import requests

## use several threads to download the F-Droid data. This is of no
## use if you are on a slow line with a bandwidth cap and it might
## actually be beneficial to use just a single thread.
def downloadfile(downloadqueue, failqueue):
        while True:
                (fdroidfile, storedirectory, filehash) = downloadqueue.get()
                try:
                        r = requests.get('https://f-droid.org/repo/%s' % fdroidfile)
                except:
                        failqueue.put(fdroidfile)
                        downloadqueue.task_done()
                        continue

                if r.status_code != 200:
                        failqueue.put(fdroidfile)
                        downloadqueue.task_done()
                        continue

                ## write the hash of the current data to the hash file
                resultfilename = os.path.join(storedirectory, fdroidfile)
                resultfile = open(resultfilename, 'wb')
                resultfile.write(r.content)
                resultfile.close()

                if filehash != None:
                        h = hashlib.new('sha256')
                        h.update(r.content)
                        if filehash != h.hexdigest():
                                os.unlink(resultfilename)
                                failqueue.put(fdroidfile)
                                downloadqueue.task_done()
                                continue
                downloadqueue.task_done()

def main(argv):
        parser = argparse.ArgumentParser()
        parser.add_argument("-c", "--config", action="store", dest="cfg", help="path to configuration file", metavar="FILE")
        args = parser.parse_args()

        ## sanity checks for the configuration file
        if args.cfg == None:
                parser.error("No configuration file provided, exiting")

        ## the configuration file should exist ...
        if not os.path.exists(args.cfg):
                parser.error("File %s does not exist, exiting." % args.cfg)

        ## ... and should be a real file
        if not stat.S_ISREG(os.stat(args.cfg).st_mode):
                parser.error("%s is not a regular file, exiting." % args.cfg)

        ## read the configuration file. This is in Windows INI format.
        config = configparser.ConfigParser()

        try:
                configfile = open(args.cfg, 'r')
                config.readfp(configfile)
        except:
                print("Cannot open configuration file, exiting", file=sys.stderr)
                sys.exit(1)

        ## set a few default values)
        storedirectory = ''

        ## then process each individual section and extract configuration options
        for section in config.sections():
                if section == 'fdroid':
                        try:
                                storedirectory = config.get(section, 'storedirectory')
                        except Exception:
                                break

                        ## The number of threads to be created to download the files,
                        ## next to the main thread. Defaults to "all availabe threads".
                        ## WARNING: this might not always be faster!
                        try:
                                threads = min(int(config.get(section, 'threads')), multiprocessing.cpu_count())
                                ## if 0 or a negative number was configured, then use all available threads
                                if threads < 1:
                                        threads = multiprocessing.cpu_count()
                        except Exception:
                                ## use all available threads by default
                                threads = multiprocessing.cpu_count()
        configfile.close()

        ## Check if the base unpack directory was declared.
        if storedirectory == '':
                print("Store directory not declared in configuration file, exiting", file=sys.stderr)
                sys.exit(1)

        ## Check if the base unpack directory exists
        if not os.path.exists(storedirectory):
                print("Store directory %s does not exist, exiting" % storedirectory, file=sys.stderr)
                sys.exit(1)

        if not os.path.isdir(storedirectory):
                print("Store directory %s is not a directory, exiting" % storedirectory, file=sys.stderr)
                sys.exit(1)

        ## Check if the base unpack directory can be written to
        try:
                testfile = tempfile.mkstemp(dir=storedirectory)
                os.unlink(testfile[1])
        except Exception as e:
                print("Base unpack directory %s cannot be written to, exiting" % storedirectory, file=sys.stderr)
                sys.exit(1)

        ## now create a directory structure inside the scandirectory:
        ## binary/ -- this is where all the binary data will be stored
        ## source/ -- this is where all source files will be stored
        ## xml/ -- this is where the XML file from F-Droid will be stored
        binarydirectory = os.path.join(storedirectory, "binary")
        if not os.path.exists(binarydirectory):
                os.mkdir(binarydirectory)

        sourcedirectory = os.path.join(storedirectory, "source")
        if not os.path.exists(sourcedirectory):
                os.mkdir(sourcedirectory)
        
        xmldirectory = os.path.join(storedirectory, "xml")
        if not os.path.exists(xmldirectory):
                os.mkdir(xmldirectory)

        downloaddate = datetime.datetime.utcnow()
        xmloutname = os.path.join(xmldirectory, "index.xml-%s" % downloaddate.strftime("%Y%m%d-%H%M%S"))

        if os.path.exists(xmloutname):
                print("XML file %s already exists, please retry later. Exiting." % xmloutname, file=sys.stderr)
                sys.exit(1)

        ## first download the XML and see if it needs to be processed by
        ## comparing it to the hash of the previous downloaded XML.
        try:
                r = requests.get('https://f-droid.org/repo/index.xml')
        except:
                print("Could not connect to F-Droid, exiting.", file=sys.stderr)
                sys.exit(1)

        if r.status_code != 200:
                print("Could not get F-Droid XML file, got code %d, exiting." % r.status_code, file=sys.stderr)
                sys.exit(1)

        ## now store the XML file for future reference
        xmloutname = os.path.join(xmldirectory, "index.xml-%s" % downloaddate.strftime("%Y%m%d-%H%M%S"))
        xmlfile = open(xmloutname, 'wb')
        xmlfile.write(r.content)
        xmlfile.close()

        ## first parse the XML data to see if it is valid XML data, else
        ## remove the XML file and exit.
        try:
                fdroidxml = xml.dom.minidom.parseString(r.content)
        except:
                os.unlink(xmloutname)
                print("Could not parse F-Droid XML, exiting.", file=sys.stderr)
                sys.exit(1)

        ## compute the SHA256 of the file to see if it is already known
        h = hashlib.new('sha256')
        h.update(r.content)
        filehash = h.hexdigest()

        ## the hash of the latest file should always be stored in a file called HASH
        hashfilename = os.path.join(storedirectory, "HASH")
        if os.path.exists(hashfilename):
                hashfile = open(hashfilename, 'r')
                oldhashdata = hashfile.read()
                hashfile.close()
                if oldhashdata == filehash:
                        print("Metadata has not changed, exiting.")
                        sys.exit(0)

        ## write the hash of the current data to the hash file
        hashfile = open(hashfilename, 'w')
        hashfile.write(filehash)
        hashfile.close()

        ## now walk the XML and grab all the files in parallel
        processmanager = multiprocessing.Manager()

        ## create a queue for scanning files
        downloadqueue = processmanager.JoinableQueue(maxsize=0)
        failqueue = processmanager.JoinableQueue(maxsize=0)
        processes = []

        ## Process the XML and put all the tasks into a queue for downloading.
        ## If there is a SHA256 hash in the XML, then it is for the APK.
        apkcounter = 0
        srccounter = 0
        for i in fdroidxml.getElementsByTagName('package'):
                apkname = ''
                apkhash = ''
                for ch in i.childNodes:
                        if ch.nodeName == 'srcname':
                                fdroidfile = ch.childNodes[0].data
                                if os.path.exists(os.path.join(sourcedirectory, fdroidfile)):
                                        continue

                                downloadqueue.put((fdroidfile, sourcedirectory, None))
                                srccounter += 1
                        elif ch.nodeName == 'hash':
                                apkhash = ch.childNodes[0].data
                        elif ch.nodeName == 'apkname':
                                apkname = ch.childNodes[0].data
                                if os.path.exists(os.path.join(binarydirectory, apkname)):
                                        continue

                if apkname != '':
                        if apkhash != '':
                                downloadqueue.put((apkname, binarydirectory, apkhash))
                        else:
                                downloadqueue.put((apkname, binarydirectory, apkhash))
                        apkcounter += 1

        ## create processes for unpacking archives
        for i in range(0,threads):
                p = multiprocessing.Process(target=downloadfile, args=(downloadqueue, failqueue))
                processes.append(p)

        ## start all the processes
        for p in processes:
                p.start()

        downloadqueue.join()

        failedfiles = []

        while True:
                try:
                        failedfiles.append(failqueue.get_nowait())
                        failqueue.task_done()
                except queue.Empty as e:
                        ## Queue is empty
                        break

        ## block here until the failqueue is empty
        failqueue.join()

        ## Done processing, terminate processes
        for p in processes:
                p.terminate()

        print("Successfully downloaded: %d files" % ((apkcounter + srccounter) - len(failedfiles)))
        print("Failed to download: %d files" % len(failedfiles))

if __name__ == "__main__":
        main(sys.argv)
