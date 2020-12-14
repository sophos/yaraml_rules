import re
import collections
import pefile
import os
import numpy as np
import sys
import traceback
from scipy import stats
from yaraml.logline import log

# string extraction regex global variables
string_regexp = '[^a-zA-Z0-9]'
pattern = re.compile(string_regexp)
MAX_RANK = 2 # shouldn't be more than 9
ENTROPY_LIMIT = 3000

def chunk_entropy(chunk):
    """
    Not currently used
    """
    bytecounts = np.zeros(256)
    for byte in chunk:
        bytecounts[int(byte)] += 1
    entropy = stats.entropy(bytecounts)
    return entropy

def get_features(path,splitstrings=True,maxtokenlen=64,mintokenlen=16,sample_rate=1.0):
    """
    Extract features from file; we'll then compute identical features in our Yara rule downstream
    :path: Path to the target file
    :splitstrings: Call python.split() on string?
    :maxtokenlen: Maximum length of feature before we throw it out
    :mintokenlen: Minimum length of feature before we throw it out
    :sample_rate: Randomly sample features to reduce feature space size?
    """

    try:
        log("Extracting features from: " + path)
        file_object = open(path,errors='ignore')
        data = file_object.read()
        binary_data = list(map(int, open(path,'rb').read()))

        special_features = {
            '@filesize': float(os.path.getsize(path))
        }

        bytecounts = np.zeros(256)
        for byte in binary_data[:ENTROPY_LIMIT]:
            bytecounts[int(byte)] += 1

        # commenting out this entropy bit, there seems to be some subtle difference between the
        # way we're computing entropy and the way Yara is computing entropy that I haven't
        # figured out yet

        #entropy = stats.entropy(bytecounts)
        #if np.isnan(entropy):
        #    entropy = 0
        #
        #special_features['@math.entropy(0,{0})'.format(ENTROPY_LIMIT)] = float(entropy)

        pe = None
        try:
            pe = pefile.PE(path)
        except:
            pass

        if pe:
            special_features['@pe.image_base'] = float(pe.OPTIONAL_HEADER.ImageBase)
            special_features['@pe.number_of_sections'] = float(pe.FILE_HEADER.NumberOfSections)
            special_features['@pe.entry_point'] = float(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
            special_features['@pe.timestamp'] = float(pe.FILE_HEADER.TimeDateStamp)

        strings = re.split(pattern,data)

        # store string features in dictionary form
        string_features = collections.defaultdict(float)
        for string in strings:
            if len(string) <= maxtokenlen and len(string) >= mintokenlen:
                hv = hash(string) % 10000
                if (hv / 10000.0) <= sample_rate:
                    string_features["$"+string] += 1.0

        string_features.update(special_features)
        return string_features
    except:
        log("".join(traceback.format_exception(*sys.exc_info())))
        return {}
