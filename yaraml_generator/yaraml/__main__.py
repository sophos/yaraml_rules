#!/usr/bin/python3

import pickle
import sys
import argparse
import os
import random
import multiprocessing
import re
import math
import numpy as np
import joblib
import os

from datetime import datetime
from sklearn import tree
from functools import partial
from yaraml import convert_tree
from yaraml import convert_linear
from yaraml.logline import log
from yaraml.features import get_features

#from matplotlib import pyplot as plt
from sklearn.feature_selection import SelectFromModel
from sklearn.feature_extraction import DictVectorizer
from sklearn.feature_selection import SelectKBest, chi2, f_classif
from sklearn.tree import export_graphviz
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_curve, auc
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split

import collections

def get_training_paths(directory,limit=None):
    # utility function to get training paths
    targets = []
    count = 0
    for root,dirs,files in os.walk(directory):
        for name in files:
            if limit and (count >= limit):
                break
            count += 1
            targets.append(os.path.join(root,name))
        if limit and (count >= limit):
            break
    return targets

def yaraified_rf_prediction(rf,tree_thres,percent_match,X):
    results = []
    for tree in rf.estimators_:
        results.append(list(tree.predict_proba(X)[:,-1] > tree_thres))
    results = np.array(results)
    results = results.transpose().sum(axis=1) / len(rf.estimators_)
    return results

def main():
    # parse arguments
    parser = argparse.ArgumentParser("Train a Yara signature")
    parser.add_argument("malware_paths",default=None,help="Path to malware training files, searched recursively")
    parser.add_argument("benignware_paths",default=None,help="Path to benignware training files, searched recursively")
    parser.add_argument("--max_benign_files",default=None,type=int,help="Sample n benign files without replacement (if not defined use all)")
    parser.add_argument("--max_malicious_files",default=None,type=int,help="Sample n malicious files without replacement (if not defined use all)")
    parser.add_argument("--retrain", action="store_true",default=False,
        help="Use this if you'd like to retrain a model using an extracted feature pickle file.  model_path must point to a directory with saved model parameters.  yaraml will load the pickle file in that directory and train a new model with the parameters you specify with --model_type or --model_instantion.  You can also change --max_features in your retrain.  This is useful in iterating on a yaraml rule until you get to an adequately performant model.")
    parser.add_argument("model_path",default=None,help="New directory to create at which to store model")
    parser.add_argument("rule_name",default=None,help="Name of rule")
    parser.add_argument("--val_percent",default=0.2,help="Percent of data to hold out for validation",type=float)
    parser.add_argument("--detection_threshold",default=0.5,help="Detection threshold to bake into rule",type=float)
    parser.add_argument("--ignore_saved_features",default=False,action="store_true",help="Ignore cached features, re-extract features")
    parser.add_argument(
        "--model_type",default="randomforest",
        choices=["randomforest","logisticregression"]
    )
    parser.add_argument(
        "--model_instantiation",
        help="Use this as an alternative to --model_type, include a line of python instantiating a RandomForestClassifier or LogisticRegression model"
    )
    parser.add_argument(
            "--max_features",
            default=512,
            type=int,
            help="Maximum number of features to use"
            )

    args = parser.parse_args()

    if not os.path.isdir(args.model_path):
        os.mkdir(args.model_path)

    if os.path.exists(os.path.join(args.model_path,"features_and_labels.pkl")) and not args.ignore_saved_features:
        saved_data = joblib.load(os.path.join(args.model_path,"features_and_labels.pkl"))
        X, y, X_val, y_val = saved_data
    else:
        # get feature vectors
        log("Loading features")

        malicious_paths = get_training_paths(args.malware_paths)[:]
        benign_paths = get_training_paths(args.benignware_paths)[:]

        if len(malicious_paths) < 1 or len(benign_paths) < 1:
            log("You need at least 1 malicious and 1 benign sample!")
            sys.exit(1)

        random.shuffle(malicious_paths)
        random.shuffle(benign_paths)

        if args.max_benign_files:
            benign_paths = benign_paths[:args.max_benign_files]

        if args.max_malicious_files:
            malicious_paths = malicious_paths[:args.max_malicious_files]

        pool = multiprocessing.Pool()
        X = pool.map(get_features,malicious_paths + benign_paths)
        y = [1 for i in range(len(malicious_paths))] + [0 for i in range(len(benign_paths))]

        X, X_val, y, y_val = train_test_split(X,y,test_size=args.val_percent)
        saved_data = [X,y,X_val,y_val]

        log("Dumping features to pickle file")
        joblib.dump(saved_data,os.path.join(args.model_path,"features_and_labels.pkl"))

    # change into model path directory for saving out results
    os.chdir(args.model_path)

    # setup DictVectorizer
    log("Creating model")
    X_temp = X
    vectorizer = DictVectorizer(dtype=np.float64)
    vectorizer.fit(X_temp)
    X_temp = vectorizer.transform(X_temp)

    if args.model_instantiation:
        estimator = RandomForestClassifier(10,min_samples_leaf=1,n_jobs=-1)
        classifier = eval(args.model_instantiation)
    elif args.model_type == "logisticregression":
        estimator = RandomForestClassifier(10,min_samples_leaf=1,n_jobs=-1)
        classifier = LogisticRegression(solver="liblinear",penalty="l1",n_jobs=-1,max_iter=10000,verbose=True,C=1)
    elif args.model_type == "randomforest":
        estimator = RandomForestClassifier(10,min_samples_leaf=1,n_jobs=-1)
        classifier = RandomForestClassifier(10,min_samples_leaf=1,n_jobs=-1)
    else:
        raise Exception("Unknown model type {0}".format(args.model_type))

    args.max_features = min(
        len(vectorizer.get_feature_names()),
        args.max_features
    )

    # downselect features
    if type(estimator) != SelectKBest:
        selector = SelectFromModel(estimator,max_features=args.max_features).fit(X_temp, y)
    else:
        log("Fitting KBest")
        estimator.fit(X_temp,y)
        log("Done")
        selector = estimator

    support = selector.get_support()
    vectorizer.restrict(support)
    X = vectorizer.transform(X)

    # train model
    classifier.fit(X,y)

    # validate model
    roc_lines = []
    if args.val_percent > 0:
        X_val = vectorizer.transform(X_val)
        if type(classifier) == RandomForestClassifier:
            scores = yaraified_rf_prediction(classifier,args.detection_threshold,0.5,X_val)
            fpr,tpr,thres = roc_curve(y_val, scores)
        else:
            scores = classifier.predict_proba(X_val)
            fpr,tpr,thres = roc_curve(y_val, scores[:,1])

        tpr_fpr_tuples = []

        for f,t,thr in zip(fpr,tpr,thres):
            if thr > 0 and thr < 1:
                if args.model_type == "logisticregression" or 'logistic' in str(args.model_instantiation).lower():
                    thr = -1 * math.log(1.0/thr-1)
                roc_line = "At a threshold of {} expect FPR {} and TPR {}".format(thr,f,t)
                log(roc_line)
                roc_lines.append(roc_line)
                tpr_fpr_tuples.append((f,t,thr))

        if len(tpr_fpr_tuples) > 5:
            tpr_fpr_tuples = tpr_fpr_tuples[::int(len(tpr_fpr_tuples)*(5./len(tpr_fpr_tuples)))]

        log("AUC: "+str(auc(fpr,tpr)))

    # build and save rule
    if type(classifier) == RandomForestClassifier:
        rule = convert_tree.convert_randomforest(args.rule_name,classifier,vectorizer.get_feature_names(),args.detection_threshold)
    else:
        rule = convert_linear.convert_linear(args.rule_name,classifier,vectorizer.get_feature_names(),args.detection_threshold)

    #print rule
    log("Writing rule to disk")
    open(args.rule_name+".yara","w+").write(rule)
    open(args.rule_name+"_fpr_tpr_data.txt","w+").write("\n".join(roc_lines))

if __name__ == '__main__':
    main()
