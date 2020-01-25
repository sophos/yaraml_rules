# Sophos AI YaraML Rules Repository -- Security ML models compiled to Yara rules for easy deployment

## Wait, what is this?

This is a repository of Yara rules that were created automatically as translations of machine learning models.  Each directory has a rule and accompanying metadata: hashes of files used in training, an accuracy diagram (a ROC curve), and a description of how the training data was gathered and what the rule is intended to detect.

## How is this better / different from other approaches to Yara rule generation?

It's not better, just different.  We take a scientific approach here, explicitly fitting a machine learning model to solve particular detection problems, and then translating that model to Yara.  That's different than more heuristic approaches to automatic Yara rule generation, and different than writing rules by hand, but every approach has its strengths and weaknesses.

One advantage of our approach is that it allows you to dial a detection threshold on each rule, so you can trade off between false positives and false negatives depending on circumstances.

## Can I use your code to train and deploy ML models via Yara?

Not yet.  Our code is too "alpha" for that yet.  We're releasing rules via this repository to gauge public interest in this project.  If there's a lot of interest, we'll make our ML-based signature generator available based on a friendly license, like BSD or Apache.
