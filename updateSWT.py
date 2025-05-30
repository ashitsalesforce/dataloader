#!/usr/bin/env python3

import requests, zipfile, io, shutil, os, sys
import subprocess
from bs4 import BeautifulSoup
from os.path import expanduser
import urllib.request
import re
import argparse
import atexit
import tempfile

####################################################################
# Prerequisites:
# - Python 3.9 or higher
# - Directory containing mvn command in PATH environment variable.
# - Python BeautifulSoup installed locally. Run 'pip3 install beautifulsoup4'
# - Python requests installed locally. Run 'pip3 install requests'
#
# Side-effects:
# - Zip content extracted in temporary directory
# - SWT jar files installed in <git clone root>/local-proj-repo subdirectories
#
# Follow-on manual steps:
# - Update version value for SWT dependencies in pom.xml with the downloaded SWT version.
#
# Outline of the steps taken:
# - Start at https://download.eclipse.org/eclipse/downloads/
# - Go to "Latest Release" section
# - Click on the first link in the "Build Name" column
# - Go to "SWT Binary and Source" section
# - Click on the links next to "Windows (64 bit version)", "Mac OSX (64 bit version)", and "Mac OSX (64 bit version for Arm64/AArch64)"
# - Extract the contents of the zip file
# - Go to the extraction folder and run mvn install:install-file command
#
####################################################################

LOCAL_REPO_DIR = "./local-proj-repo"
TEMP_DIR = None

def is_exe(fpath):
    return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

def cleanupBeforeExit():
    if TEMP_DIR and os.path.exists(TEMP_DIR):
        shutil.rmtree(TEMP_DIR)
        
def exitWithError(errorStr):
    print(errorStr)
    sys.exit(-1)

###########################################################

def getSWTDownloadLinkForPlatform(soup, platformString):
    results = soup.find(id="SWT").find_next("td").string
    while results != None and results != platformString :
        results = results.find_next("td").string

    if results == platformString :
        results = results.find_next("a")['href']

    return results

######## end of getSWTDownloadLinkForPlatform ##########

def downloadAndExtractZip(url):
    zipfileName = url.split('=',1)[1]
    unzippedDirName = os.path.join(TEMP_DIR, zipfileName.removesuffix('.zip'))

    page = requests.get(url)
    soup = BeautifulSoup(page.content, "html.parser")
    zipURL = soup.find("meta").find_next("a")['href']

    page = requests.get(zipURL)
    soup = BeautifulSoup(page.content, "html.parser")
    divWithZip = soup.find("div", {"class":"mirror-well"})
    zipURL = divWithZip.find_next("a")['href']
    zipURL = "https://www.eclipse.org/downloads/" + zipURL

    # navigate the redirect to the actual mirror
    page = requests.get(zipURL)
    soup = BeautifulSoup(page.content, "html.parser")
    zipURL = soup.find('meta', attrs={'http-equiv': 'Refresh'})['content'].split(';')[1].split('=')[1]
    
    # delete existing content
    if os.path.exists(unzippedDirName) and os.path.isdir(unzippedDirName):
        shutil.rmtree(unzippedDirName)
    response = requests.get(zipURL, stream=True)
    z = zipfile.ZipFile(io.BytesIO(response.content))
    z.extractall(unzippedDirName)
    subprocess.run(["zip", 
                    "-d", 
                    unzippedDirName + "/swt.jar",
                    "META-INF/ECLIPSE_.SF",
                    "META-INF/ECLIPSE_.DSA",
                    "META-INF/ECLIPSE_.RSA"])

    return unzippedDirName

######## end of downloadAndExtractZip ##########

def installInLocalMavenRepo(unzippedSWTDir, mvnArtifactId, gitCloneRootDir):
    swtVersion = unzippedSWTDir.split('-')[1]

    if shutil.which("mvn") == None :
        exitWithError("did not find mvn command in the execute path")
        
    mavenCommand = "mvn install:install-file " \
                    + "-Dfile=" + unzippedSWTDir + "/swt.jar " \
                    + "-DgroupId=local.swt " \
                    + "-DartifactId=" + mvnArtifactId + " " \
                    + "-Dversion=" + swtVersion + " " \
                    + "-Dpackaging=jar " \
                    + "-Dmaven.repo.local=" + gitCloneRootDir + "/local-proj-repo"
    subprocess.run(mavenCommand, shell=True)

######## end of installInLocalMavenRepo  ##########

def getLocalSWTVersion(mvnArtifactId):
    localSWTVersion = ""
    artifactPath = os.path.join(LOCAL_REPO_DIR, "local/swt", mvnArtifactId)
    if os.path.isdir(artifactPath):
        # Look for version directories (they should be numeric)
        subdirs = [d for d in os.listdir(artifactPath) 
                  if os.path.isdir(os.path.join(artifactPath, d))]
        if subdirs:
            localSWTVersion = subdirs[0]  # Take the first version directory
            print(f"Found local version for {mvnArtifactId}: {localSWTVersion}")
    return localSWTVersion

def updateSWT(mvnArtifactId, downloadPageLabel, gitCloneRootDir, version, forceUpdate):
    URL = "https://download.eclipse.org/eclipse/downloads/"
    page = requests.get(URL)

    soup = BeautifulSoup(page.content, "html.parser")
    linkToVersionDownload = ""
    
    localSWTVersion = getLocalSWTVersion(mvnArtifactId)
    
    if version == "" :
        anchorElement = soup.find(id="Latest_Release").find_next("a")
        linkToVersionDownload = anchorElement['href']
        version = anchorElement.text
        print(f"Found download version: {version}")
    else:
        for link in soup.findAll('a', href=True):
            if version in link.text :
                linkToVersionDownload = link['href']
                break

    print(f"Comparing versions - Local: '{localSWTVersion}', Download: '{version}'")
    if not forceUpdate and version.strip() == localSWTVersion.strip():
        print(f"Skipping download for {mvnArtifactId} - version {version} already installed")
        return

    if linkToVersionDownload == "" :
        exitWithError("version " + version + " not found for download")

    downloadsPage = URL + linkToVersionDownload
    page = requests.get(downloadsPage)
    soup = BeautifulSoup(page.content, "html.parser")
    
    results = getSWTDownloadLinkForPlatform(soup, downloadPageLabel)
    unzippedDir = downloadAndExtractZip(downloadsPage + results)
    installInLocalMavenRepo(unzippedDir, mvnArtifactId, gitCloneRootDir)

######## end of updateSWTAndPOM #########################

atexit.register(cleanupBeforeExit)

parser = argparse.ArgumentParser(description = "my parser")
parser.add_argument("-v", "--version", required = False, default = "")
parser.add_argument("-f", "--force", required = False, default = False, nargs='?', const=True)
parser.add_argument("-c", "--cloneroot", required = False, default = os.getcwd())

arguments = parser.parse_args()

# initialize variables from arguments
version = arguments.version
rootdir = arguments.cloneroot
forceUpdate = arguments.force

# Create temporary directory for downloads
TEMP_DIR = tempfile.mkdtemp()
print(f"Created temporary directory: {TEMP_DIR}")

# Windows x86
updateSWT("swtwin32_x86_64", "Windows (x86 64-bit)", rootdir, version, forceUpdate)

# Windows ARM
updateSWT("swtwin32_aarch64", "Windows (ARM 64-bit)", rootdir, version, forceUpdate)

# Mac x86
updateSWT("swtmac_x86_64", "Mac OSX (x86 64-bit)", rootdir, version, forceUpdate)

# Mac ARM
updateSWT("swtmac_aarch64", "Mac OSX (ARM 64-bit)", rootdir, version, forceUpdate)

# Linux x86
updateSWT("swtlinux_x86_64", "Linux (x86 64-bit)", rootdir, version, forceUpdate)

# Linux ARM
updateSWT("swtlinux_aarch64", "Linux (ARM 64-bit)", rootdir, version, forceUpdate)

# Clean up temporary directory
if os.path.exists(TEMP_DIR):
    shutil.rmtree(TEMP_DIR)

# Clean up any non-local directories in the local repo
for subdir in os.listdir(LOCAL_REPO_DIR):
    if subdir != "local":
        shutil.rmtree(os.path.join(LOCAL_REPO_DIR, subdir))
