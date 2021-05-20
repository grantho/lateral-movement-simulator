# This module contains various utility methods

import itertools
import random
import networkx as nx
from collections import *
from itertools import groupby

from data_types import *

#########################################
#########################################
#########################################
# TODO: Fill in the methods below w/ org specific implementation

# Helper method to get organization specific data

def get_all_users():
    """Return a set of all employee user names."""
    pass


def get_sysadmin_users():
    """Return a set of all sysadmin user names."""
    pass

# Data Filtering Methods

def is_server_jump_host(machine):
    """Is the machine a jump host that doesn't allow cred switching?"""
    pass

def remove_spurious_logins(logins):
    """Remove logins between equivalent machines or from management into clients."""
    pass

def is_compromisable_host(machine, non_viable_machines=set([])):
    """Assess whether machine IS viable compromise point / intermediate path node."""
    return not (is_server_jump_host(machine) or machine in non_viable_machines)


#########################################


def create_login_graph(logins):
    """Create a networkx object that encapsulates logins in the graph."""
    logins = remove_spurious_logins(logins)
    src_dst = logins[[LoginColumns.SRC, LoginColumns.DST]].drop_duplicates()
    src_dst = [(r[LoginColumns.SRC], r[LoginColumns.DST]) for idx, r in src_dst.iterrows()]
    login_graph = nx.DiGraph(src_dst)
    return login_graph


#########################################
# Generic Helper functions for data processing

def flatten_list(list_of_lists):
    """Flatten a list of lists into a single list"""
    return list(itertools.chain(*list_of_lists))

def safe_rand_sample(item_list, num_samples):
    return random.sample(item_list, min(num_samples, len(item_list)))

def df_to_grouped_dict(df, key_cols, value_col, agg_func):
    """Group a dataframe into a dict {(key col's) -> agg_func([value_col's])}."""
    return df.groupby(key_cols)[value_col].agg(agg_func).to_dict()


#########################################
# Generic Helper functions for IO/printing

def print_small_divider():
    print("-----------------------------------------------------\n")


def print_divider():
    """Print a divider line"""
    print("================================================================\n")


def comma_num(number):
    """Return a str w/ a comma for every thousands."""
    return "{:,}".format(number)
