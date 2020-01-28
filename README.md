# Sophos AI YaraML Rules Repository


## Wait, what is this?

This is a repository of Yara rules that were created automatically as translations of machine learning models.  Each directory has a rule and accompanying metadata: hashes of files used in training, an accuracy diagram (a ROC curve), and a description of how the training data was gathered and what the rule is intended to detect.


## How is this better / different from other approaches to Yara rule generation?

It's not better, just different.  Machine learning has some nice properties: let's you dial a detection threshold to trade off between false positives and false negatives, and often produces superior detection rates when it has a lot of training data.  When we only have a single example of a malicious family, humans can probably write better rules.


## Can I use your code to train and deploy ML models via Yara?

Not yet.  Our code is too "alpha" for that yet.  We're releasing rules via this repository to gauge public interest in this project.  If there's a lot of interest, we'll make our ML-based signature generator available based on a friendly license.
