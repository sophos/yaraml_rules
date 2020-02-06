# v0.1 Random Forest Mach-O Malware Detector
*Questions, concerns, ideas, results, feedback appreciated, please email joshua.saxe@sophos.com*

An initial try at a malicious Mach-O detector, trained on 20k binaries, 15k benign, 5k malicious.  Detects malware that it *wasn't trained on* at a 89.2% detection rate and a 0.7% false positive rate.  Use this to hunt for dodgy binaries on OSX endpoints that your security product may have missed.
