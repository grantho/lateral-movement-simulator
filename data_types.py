# This module contains various constants, classes, and data types.

import pandas as pd
from collections import namedtuple


class LoginColumns(object):
    """Column name constants for Pandas data."""
    TIME = "time"
    INDEX_TIME = 'indextime'

    SRC = "src"
    DST = "dst"
    USER = "user"

    MOVEMENT_TYPE = "movement_type"
    PROTOCOL = 'protocol'  # ssh vs. Windows
    DATASET = "dataset"

    # Labeling
    ATTACK = 'is_attack'  # groundtruth label: attack == True, else False
    ATTACK_ID = 'attack_id'  # ID for synthetic attack this corresponds to


class EnrichmentColumns(object):
    """Class for defining intermediate/enrichment related columns."""
    # Src labeling
    SRC_SUBNET = 'src_subnet'
    SRC_LOCATION = "src_location"
    LOCATION = "location"

    # Machine Age: first date appeared
    MACHINE_AGE = "machine_age"
    MACHINE_EARLIEST_DATE = "machine_first_date"

    # Node Attribute Labeling
    NUM_INBOUND_DAYS = "src_n_days_recv_inbound_success"
    SRC_CLIENT = "is_src_client"
    DST_CLIENT = "is_dst_client"
    SRC_OWNER = "owner"

    # USER Features
    USER_TEAM = "user_team"
    USER_AGE = "user_age"  # how many days since LOCAL LOGIN or remote login


class MovementTypes(object):
    MOVE_FROM_CLIENT = "movement:client-server"
    MOVE_INTO_CLIENT = "movement:into-client"
    MOVE_FROM_SERVER = "movement:server-server"


class ScenarioConstants(object):
    GOAL_EXPLORATION = "goal=exploration"
    GOAL_SPREAD = "goal=aggressive-spread"
    GOAL_TARGETED = "goal=targeted"

    STEALTH_NONE = "stealth=agnostic"
    STEALTH_ENDPOINTS = "stealth=only-prev-src-dst-combos"
    STEALTH_ACTIVE_CREDS = "stealth=only-active-src-user-combos"
    STEALTH_FULL = "stealth=full-stealthiness"


#########################################
# Base classes
#########################################

class LoggingClass(object):
    """Enable different logging output."""
    def __init__(self, verbose=True):
        self.verbose=verbose

    def log(self, msg):
        """HELPER Method: Log message depending on verbose or not."""
        if self.verbose:
            print(msg)


class AttackHistory(LoggingClass):
    """Track history + state of the attack."""
    def __init__(self, start_state, verbose=True):
        super(AttackHistory, self).__init__(verbose=verbose)
        self.start_state = start_state

        # Track attack history
        self.attack_path = pd.DataFrame()
        self.num_hops = 1

        # which creds were compr. on which machines
        self.compromised_creds_per_dst = dict()
        self.visited_dst = set([self.start_state.start_src,])
        self.cur_machine = self.start_state.start_src
        self.cur_user = self.start_state.start_user
        self.last_move_time = self.start_state.start_time

    def get_start_accessible_dst(self):
        """Get a set of machines that start user has permissions to access."""
        return self.start_state.start_accessible_dst

    def get_start_src(self):
        return self.start_state.start_src

    def get_start_user(self):
        return self.start_state.start_user

    def get_current_user(self):
        return self.cur_user

    def get_current_machine(self):
        return self.cur_machine

    def get_visited_dst(self):
        return self.visited_dst

    def add_new_hop(self, new_hop):
        """Update attack history with new hop."""
        self.attack_path = pd.concat([self.attack_path, new_hop], sort=False)
        self.cur_user = new_hop[LoginColumns.USER].iloc[0]

        new_machine = new_hop[LoginColumns.DST].iloc[0]
        self.cur_machine = new_machine
        self.visited_dst.add(new_machine)

        self.last_move_time = new_hop[LoginColumns.TIME].iloc[0]
        self.num_hops += 1

    def update_compromised_creds(self, machine, compromised_creds):
        """Update compromised creds per machine."""
        self.compromised_creds_per_dst[machine] = self.compromised_creds_per_dst.get(
            machine, set([])
        ) | compromised_creds


AttackNextHop = namedtuple(
    'AttackNextHop', [LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER])
