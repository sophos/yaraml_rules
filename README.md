# Sophos AI YaraML Rules Repository
*Questions, concerns, ideas, results, feedback appreciated, please email joshua.saxe@sophos.com*

A repository of Yara rules that created automatically as translations of machine learning models.  Each directory has a rule and accompanying metadata: hashes of files used in training, an accuracy diagram (a ROC curve), and a description of how the training data was gathered and what the rule is intended to detect.

Here's an example ML (logistic regression) rule, for detecting malicious powershell:

```
rule Generic_Powershell_Detector
{
strings:
...
$s4 = "DownloadFile"       fullword // weight: 3.257
$s5 = "WOW64"              fullword // weight: 3.232
$s6 = "bypass"             fullword // weight: 3.021
$s7 = "meMoRYSTrEaM"       fullword // weight: 2.68
$s8 = "obJEct"             fullword // weight: 2.679
$s9 = "OBJecT"             fullword // weight: 2.659
$s10 = "ReGeX"              fullword // weight: 2.592
$s11 = "samratashok"        fullword // weight: 2.548
$s12 = "Dependencies"       fullword // weight: 2.494
$s13 = "TVqQAAMAAAAEAAAA"   fullword // weight: 2.428
$s14 = "CompressionMode"    fullword // weight: 2.366
...
condition:
...
((#s0 * 5.567) + (#s1 * 4.122) + (#s2 * 3.904) + (#s3 * 3.820) + 
(#s4 * 3.257) + (#s5 * 3.232) + (#s6 * 3.021) + (#s7 * 2.680) + 
(#s8 * 2.679) + (#s9 * 2.659) + (#s10 * 2.592) + (#s11 * 2.548) + 
...
> 0
}
```

Here's the ROC curve this rule achieves.  You can move around in ROC space by changing the threshold after the '>' sign at the end of the file.
![Powershell ROC curve](https://github.com/inv-ds-research/yaraml_rules/blob/master/generic_powershell_detector_jan28_2020/validation_roc_with_recommended_thresholds.png?raw=true)


## Why?

Because ML rules are a good complement to hand-written rules.  Machine learning has some nice properties: let's you dial a detection threshold to trade off between false positives and false negatives, and often produces superior detection rates when it has a lot of training data.  When we only have a few examples of a malicious family, expert humans can probably write better rules.

## Can I use your code to train and deploy ML models via Yara?

Not yet.  Our code is too "alpha" for that yet.  We're releasing rules via this repository to gauge public interest in this project.  If there's a lot of interest, we'll make our ML-based signature generator available based on a friendly license.
