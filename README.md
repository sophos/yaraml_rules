# Sophos AI YaraML Rules Repository


## Wait, what is this?

This is a repository of Yara rules that were created automatically as translations of machine learning models.  Each directory has a rule and accompanying metadata: hashes of files used in training, an accuracy diagram (a ROC curve), and a description of how the training data was gathered and what the rule is intended to detect.

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
((#s0 * 5.567) + (#s1 * 4.122) + (#s2 * 3.904) + (#s3 * 3.820) + (#s4 * 3.257) + (#s5 * 3.232) + (#s6 * 3.021) + (#s7 * 2.680) + (#s8 * 2.679) + (#s9 * 2.659) + (#s10 * 2.592) + (#s11 * 2.548) + (#s12 * 2.494) + (#s13 * 2.428) + (#s14 * 2.366) + (#s15 * 2.350) + (#s16 * 2.341) + (#s17 * 2.340) + (#s18 * 2.340) + (#s19 * 2.218) + (#s20 * 2.003) + (#s21 * 1.960) + (#s22 * 1.883) + (#s23 * 1.830) + (#s24 * 1.828) + (#s25 * 1.781) + (#s26 * 1.730) + (#s27 * 1.727) + (#s28 * 1.723) + (#s29 * 1.647) + (#s30 * 1.484) + (#s31 * 1.457) + (#s32 * 1.448) + (#s33 * 1.419) + (#s34 * 1.418) + (#s35 * 1.373) + (#s36 * 1.339) + (#s37 * 1.322) + (#s38 * 1.302) + (#s39 * 1.243) + (#s40 * 1.204) + (#s41 * 1.202) + (#s42 * 1.190) + (#s43 * 1.188) + (#s44 * 1.178) + (#s45 * 1.170) + (#s46 * 1.153) + (#s47 * 1.141) + (#s48 * 1.097) + (#s49 * 1.097) + (#s50 * 1.094) + (#s51 * 1.085) + (#s52 * 1.062) + (#s53 * 1.017) + (#s54 * 1.014) + (#s55 * 1.011) + (#s56 * 1.006) + (#s57 * 1.000) + (#s58 * 0.978) + (#s59 * 0.962) + (#s60 * 0.961) + (#s61 * 0.958) + (#s62 * 0.958) + (#s63 * 0.954) + (#s64 * 0.914) + (#s65 * 0.908) + (#s66 * 0.887) + (#s67 * 0.884) + (#s68 * 0.828) + (#s69 * 0.800) + (#s70 * 0.795) + (#s71 * 0.789) + (#s72 * 0.788) + (#s73 * 0.756) + (#s74 * 0.753) + (#s75 * 0.745) + (#s76 * 0.745) + (#s77 * 0.722) + (#s78 * 0.689) + (#s79 * 0.638) + (#s80 * 0.628) + (#s81 * 0.623)
...
}
```

## How is this better / different from other approaches to Yara rule generation?

It's not better, just different.  Machine learning has some nice properties: let's you dial a detection threshold to trade off between false positives and false negatives, and often produces superior detection rates when it has a lot of training data.  When we only have a single example of a malicious family, humans can probably write better rules.


## Can I use your code to train and deploy ML models via Yara?

Not yet.  Our code is too "alpha" for that yet.  We're releasing rules via this repository to gauge public interest in this project.  If there's a lot of interest, we'll make our ML-based signature generator available based on a friendly license.
