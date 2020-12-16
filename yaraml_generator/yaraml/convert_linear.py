#!/usr/bin/python

import pickle
import numpy as np
import networkx
import json
import itertools
import pprint

from yaraml.logline import log
from networkx.drawing.nx_pydot import write_dot
from networkx.algorithms.shortest_paths.generic import shortest_path

def convert_linear(rulename,estimator,feature_names,malware_threshold=0.5,private=True):
    coefs = list(zip(estimator.coef_[0,:],feature_names))
    bias = estimator.intercept_[0]
    feature_weights = []
    symbol_weights = []
    for weight, feature in coefs:
        if abs(weight) > 0.001:
            feature_weights.append((feature,weight))

    feature_weights.sort(key=lambda x:x[1],reverse=True)

    stringdata = "\n".join(["\t$s{} = {:20} fullword // weight: {:.4}".format(i,json.dumps(j[0][1:]),j[1]) for i,j in enumerate(feature_weights)])

    conditiondata = []
    for idx, (feature, coef) in enumerate(feature_weights):
        conditiondata.append("(#s{0} * {1:.3f})".format(idx,coef))
    log("DEBUG: Linear model bias term is: " + str(bias))
    if abs(bias) > 0.001:
        conditiondata.append("({0:.3f})".format(bias))
    conditions = "\t"+"(" + " + ".join(conditiondata) + ")"
    conditions += " > 0"

    rule = """rule %s
{
    strings:
%s

    condition:
%s

}
""" % (rulename,stringdata,conditions)

    log("Here's the rule we're writing to disk:\n" + "*"*30 + "\n\n" + rule)
    return rule
