
def convertFILETIMEtoEpoch(t):
    return (t - 116444736000000000) / 10000000.0;

def convertEpochToFILETIME(t):
    return int(t * 10000000.0) + 116444736000000000
