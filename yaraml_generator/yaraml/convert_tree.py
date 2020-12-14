#!/usr/bin/python

import pickle
import numpy as np
import networkx
import json
import itertools
from networkx.drawing.nx_pydot import write_dot
from networkx.algorithms.shortest_paths.generic import shortest_path

string_symbol_cache = {}
def convert_tree(rulename,estimator,feature_names,malware_threshold=0.5):
    """
    Convert a sklearn decision tree into a Yara rule
    rulename: Name of your Yara rule
    estimator: Your model
    feature_names: List in column order of your features
    malware_threshold: P(malware|features) threshold for leaf nodes to evaluate as 'true'
    """

    global string_symbol_cache
    string_symbol_cache = {}
    n_nodes = estimator.tree_.node_count
    children_left = estimator.tree_.children_left
    children_right = estimator.tree_.children_right
    feature = estimator.tree_.feature
    threshold = estimator.tree_.threshold
    treegraph = networkx.DiGraph()

    node_depth = np.zeros(shape=n_nodes, dtype=np.int64)
    is_leaves = np.zeros(shape=n_nodes, dtype=bool)
    stack = [(0, -1)]  # seed is the root node id and its parent depth
    while len(stack) > 0:
        node_id, parent_depth = stack.pop()
        node_depth[node_id] = parent_depth + 1

        # If we have a test node
        if (children_left[node_id] != children_right[node_id]):
            stack.append((children_left[node_id], parent_depth + 1))
            stack.append((children_right[node_id], parent_depth + 1))
        else:
            is_leaves[node_id] = True

    target_nodes = []
    for i in range(n_nodes):
        if is_leaves[i]:
            malware_prob = float(estimator.tree_.value[i][0][1]/estimator.tree_.value[i][0].sum())
            treegraph.add_node(
                i,
                value=list(estimator.tree_.value[i][0]),
                malware_prob=malware_prob,
                fname=feature_names[feature[i]],type="leaf",
                label=repr(estimator.tree_.value[i][0])+" "+repr(malware_prob)
            )
            if malware_prob >= malware_threshold:
                target_nodes.append(i)
        else:
            treegraph.add_node(i,value=list(estimator.tree_.value[i][0]),
                    fname=feature_names[feature[i]],type="split",label=feature_names[feature[i]])

    for i in range(n_nodes):
        if not is_leaves[i]:
            treegraph.add_edge(i,children_left[i],split_type="false",label="false",threshold=threshold[i])
            treegraph.add_edge(i,children_right[i],split_type="true",label="true",threshold=threshold[i])

    root_node = list(networkx.topological_sort(treegraph))[0]
    stringset = set()
    yara_paths = []

    # prune tree to preserve only paths that get us to a detection leaf
    nodes_to_retain = set()
    for node in target_nodes:
        path = shortest_path(treegraph,root_node,node)
        for node in path:
            nodes_to_retain.add(node)
    nodes_to_remove = set()
    for node in treegraph:
        if not node in nodes_to_retain:
            nodes_to_remove.add(node)
    for node in nodes_to_remove:
        treegraph.remove_node(node)

    # build tree logic recursively
    def recurse(n1,depth=0):
        descendants = treegraph.successors(n1)
        tab = " "*depth
        or_strings = []
        for n2 in descendants:
            condition = treegraph.get_edge_data(n1,n2)['split_type']
            threshold = treegraph.get_edge_data(n1,n2)['threshold']
            n1fname = treegraph.nodes(data=True)[n1]['fname']

            feature_type = None
            if n1fname.startswith("$"):
                feature_type = "string"
                if n1fname in string_symbol_cache:
                    nodesymbol = string_symbol_cache[n1fname]
                else:
                    nodesymbol = "#s{0}".format(n1)
                    string_symbol_cache[n1fname] = nodesymbol
                stringset.add((nodesymbol,n1fname[1:]))
            elif n1fname.startswith("@"):
                feature_type = "special"
                nodesymbol = "{0}".format(n1fname[1:])
            else:
                raise Exception("Unknown feature type")

            if condition == "false":
                yara_condition = "({0} <= {1})".format(nodesymbol,threshold)
            else:
                yara_condition = "({0} > {1})".format(nodesymbol,threshold)
            descendant = recurse(n2,depth+1)
            if descendant:
                or_strings.append((yara_condition, descendant))
            else:
                or_strings.append((yara_condition, None))

        retstrings = []
        for idx, (yara_condition,descendant) in enumerate(or_strings):
            if yara_condition and descendant:
                retstrings.append(tab+yara_condition+"\n"+" and "+descendant)
            elif yara_condition:
                retstrings.append(tab+yara_condition+"\n")

        if len(retstrings):
            retstring = "("+" or ".join(retstrings)+")"
        else:
            retstring = None
        return retstring

    conditiondata = recurse(root_node)

    template = """
private rule %s
{
    strings:
%s

    condition:
%s
}
"""
    sorted_strings = sorted(list(stringset),key=lambda x:int(x[0][2:].split()[0]))
    stringdata = "\n".join(["\t\t{0} = {1} fullword".format(i.replace("#","$"),json.dumps(j)) for i,j in sorted_strings])

    rule = template % (rulename,stringdata,conditiondata)
    return rule


def convert_randomforest(rulename,estimator,features,percent_match_threshold=0.9, tree_prob_threshold=0.5):
    """
    Convert an sklearn random forest into a Yara rule
    :estimator: your model
    :features: your features
    :percent_match_threshold: Number of trees that need to evaluate as 'true' to declare an input malware
    :tree_prob_threshold: Leaf node P(malware|features) threshold for a tree to evaluate as 'true'
    """
    rulelist = []
    names = []
    for idx,tree in enumerate(estimator.estimators_):
        name = "tree{0}".format(idx)
        names.append(name)
        rulelist.append(convert_tree(name,tree,features,tree_prob_threshold))
    rule = "\n\n".join(rulelist)
    rule += "\n\n"

    rule = 'import "math"\n' + rule
    if "pe." in rule:
        rule = 'import "pe"\n' + rule

    template = """
rule %s
{
    condition:
%s
}
    """
    combination_size = int(len(estimator.estimators_) * percent_match_threshold)
    #combination_size = len(estimator.estimators_) - 1
    conditions = []
    for combination in itertools.combinations(names, combination_size):
        condition = "("+" and ".join(combination)+")"
        conditions.append(condition)
    conditiondata = "\t"+"\n\t\t or ".join(conditions)

    rule += template % (rulename, conditiondata)

    return rule
