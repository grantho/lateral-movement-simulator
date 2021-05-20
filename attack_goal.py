# This module encapsulates code for shaping the attack to a given goal
# and when the attack should terminate.

import networkx as nx   # for computing targeted attack paths

from data_types import *
from utils import *


class MovementGoal(LoggingClass):
    """Specify attack's goal and choose next hop accordingly."""
    MAX_HOPS = 50
    GOAL_EXPLORATION = ScenarioConstants.GOAL_EXPLORATION
    GOAL_SPREAD = ScenarioConstants.GOAL_SPREAD
    GOAL_TARGETED = ScenarioConstants.GOAL_TARGETED

    def __init__(self, goal, target_machines=set([]), verbose=True):
        """Configure attack's goal.

        Args:
            goal: GOAL_ constant in this class
            target_machines: set of str's (hostnames)
        """
        super(MovementGoal, self).__init__(verbose=verbose)
        self.goal = goal
        self.target_info = TargetingInfo(target_machines)
        self.compromised_priv_users = set([])

        self.log("Attack Goal = {}\tTarget machines = {}\n".format(
            self.goal, target_machines
        ))

    def select_next_hop(self, candidate_next_hops, attack_history, attack_capabilities):
        """Select next hop based on combination of goal + attack progress & capabilities.

        Args:
            candidate_next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
            attack_capabilities: attack_capabilities.AttackerCapabilities object
        """
        self.log("Next hop (Goal): Selecting next hop from "
                 "{} candidate hops.\n".format(len(candidate_next_hops)))
        if self.goal == self.GOAL_TARGETED:
            # Done: Jul 27, 2020
            candidate_next_hops = self._constrain_hops_for_targeted(
                candidate_next_hops, attack_history, attack_capabilities)
        elif self.goal == self.GOAL_SPREAD:
            # Done: Jul 11, 2020
            candidate_next_hops = self._constrain_hops_for_aggressive_spread(
                candidate_next_hops, attack_history)
        elif self.goal == self.GOAL_EXPLORATION:
            # Done
            self.log("Next hop (Goal): Exploration lateral movement; "
                     "selecting next hop from candidates without additional constraints.")

        # Default to preferring movement from the current server if available, or
        # from the initial foothold machine
        preferred_hops = [
            hop for hop in candidate_next_hops if (
                hop.src == attack_history.get_current_machine() or
                hop.src == attack_history.get_start_src()
            )
        ]
        if len(preferred_hops) > 0:
            candidate_next_hops = preferred_hops

        self.log("Next hop (Goal): {} candidate next hops based on goal = {}.".format(
                 len(candidate_next_hops), self.goal))

        next_hop = safe_rand_sample(candidate_next_hops, 1)
        if next_hop is not None and len(next_hop) == 1:
            return next_hop[0]

        return AttackNextHop(None, None, None)

    def is_attack_complete(self, attack_history):
        """Check if attack has completed.

        Args:
            attack_history: data_types.AttackHistory object
        """
        if attack_history is None:
            return False
        elif attack_history.num_hops > self.MAX_HOPS:
            self.log("\nWARNING: Terminating attack because movement exceeds "
                     "max hop limit of {}.\n".format(self.MAX_HOPS))
            return True

        if self.goal == self.GOAL_EXPLORATION:  # != self.GOAL_TARGETED:
            # If the goal is not targeted (OR spread), then terminate the attack
            # once the attacker switches to using a new set of credentials
            return (
                attack_history.num_hops > 1 and
                (attack_history.get_start_user() != attack_history.get_current_user())
            )
        elif self.goal == self.GOAL_SPREAD:
            # For aggressive spread, all attack to continue to max
            # or until no next hops exist (handled by invoking loop)
            return attack_history.num_hops > self.MAX_HOPS
        elif (
            self.goal == self.GOAL_TARGETED and
            self.target_info.initialized and
            (len(self.target_info.paths_to_priv_users) == 0)
        ):
            # If the goal is targeted AND there is NO viable path to credentials
            # w/ permissions to target machine, terminate the attack
            self.log(
                "\nWARNING: Terminating attack because NO viable path "
                "exists to a machine with exposed priv users = {} "
                "from src = {}\n".format(
                    self.target_info.priv_users, attack_history.get_start_src()
            ))
            return True
        else:
            # If the goal is targeted and there is a viable path to necessary creds,
            # then the attack terminates once we've arrived at a target machine
            return attack_history.cur_machine in self.target_info.target_machines

    def update_progress(self, new_dst, compromised_users):
        """Update if any newly compr users are desired privileged users.

        Not currently using (7/27/2020) new_dst, but could in future.

        Args:
            new_dst: (str)
            compromised_users: set of str's (usernames)
        """
        self.compromised_priv_users = \
            compromised_users.intersection(self.target_info.priv_users)

    def _targeted_priv_users_compromised(self):
        """Check whether targeted attack has compromised priv users."""
        return len(self.compromised_priv_users) > 0

    def _constrain_hops_for_targeted(
        self, next_hops, attack_history, attack_capabilities
    ):
        """Constrain candiate hops to pursue access to targeted dst.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
            attack_capabilities: attack_capabilities.AttackerCapabilities object
        """
        if len(self.compromised_priv_users) == 0:
            # If attack has NOT yet compromised necessary creds, follow paths
            # that lead to such creds
            next_hops = [
                hop for hop in next_hops
                if self.target_info.next_hop_go_to_priv_users(hop.dst)
            ]
            self.log("Next hop (Targeted Goal): Restricting next hops to those "
                     "that go to dst w/ priv creds: {} candidate hops "
                     "(viable stepping stone dst = {}).\n".format(
                     len(next_hops), self.target_info.nodes_to_priv_users))
            return next_hops

        # If necessary creds already compromised, switch to moving along
        # a path to target machine(s)
        next_hops = [
            hop for hop in next_hops
            if self.target_info.next_hop_go_to_target_dsts(hop.dst)
        ]
        self.log("Next hop (Targeted Goal): Restricting next hops to those "
                 "that lead to target dsts: {} candidate hops "
                 "(viable stepping stone dst = {}).\n".format(
                 len(next_hops), self.target_info.nodes_to_targets))

        # If a hop directly to target machine is available, take it.
        final_hops = [
            hop for hop in next_hops if hop.dst in self.target_info.target_machines
        ]
        if len(final_hops) > 0:
            next_hops = final_hops

        return next_hops

    def _constrain_hops_for_aggressive_spread(self, next_hops, attack_history):
        """Constrain candidate hops to follow attack goal / strategy.

        Max-out (fully explore) dest enabled by each credential before switching:
        If there are available dest for the start user creds to visit,
        then continue exploration; otherwise don't winnow candidate hops.
        """
        cur_user = attack_history.get_current_user()
        cur_user_hops = self._get_hops_for_user(next_hops, cur_user)
        if cur_user_hops is not None and len(cur_user_hops) > 0:
            next_hops = cur_user_hops
            self.log("Next hop (Goal): Select dst from remaining machines that victim #0 can access.")
        else:
            self.log(
                "Next hop (Goal): Victim #0's initial dst set completely visited."
                " Selecting next hop randomly from all candidates.")

        return next_hops

    def _get_hops_for_user(self, next_hops, user):
        """Winnow next hops down to only those that involve 'user'."""
        return [hop for hop in next_hops if hop.user == user]


class TargetingInfo(LoggingClass):
    """Encapsulate state for targeted attack / info."""
    MAX_PATH_LEN = 5

    def __init__(self, target_machines, verbose=True):
        super(TargetingInfo, self).__init__(verbose=verbose)
        self.initialized = False
        self.target_machines = target_machines
        self.start_user = None
        self.login_graph = None

        self.priv_users = set([])
        self.paths_to_priv_users = []
        self.paths_to_targets = []

        self.nodes_to_priv_users = set([])
        self.nodes_to_targets = set([])

    def initialize(self, start_src, start_time, logins):
        """Compute data structures."""
        self.log(
            "\nTargetingInfo: Precomputing paths to viable creds & target dst:\t"
            "start: {} to dsts = {}.\n".format(start_src, self.target_machines)
        )
        self.login_graph = self.create_login_graph(logins)
        self.priv_users = self.get_priv_users(self.target_machines, logins)
        self.paths_to_priv_users = self.get_paths_to_priv_users(
            start_src, self.priv_users, logins, login_graph=self.login_graph)
        self.paths_to_targets = self.get_stealthy_paths(
            start_src, self.target_machines, logins, login_graph=self.login_graph)

        self.nodes_to_priv_users = set(flatten_list(self.paths_to_priv_users))
        self.nodes_to_targets = set(flatten_list(self.paths_to_targets))
        self.initialized = True

    def next_hop_go_to_priv_users(self, next_dst):
        """Check if next dst moves along a path to priv users."""
        return next_dst in self.nodes_to_priv_users

    def next_hop_go_to_target_dsts(self, next_dst):
        """Check if next dst moves along a path to priv users."""
        return next_dst in self.nodes_to_targets or next_dst in self.target_machines

    @classmethod
    def create_login_graph(cls, logins):
        """Create a networkx object that encapsulates logins in the graph."""
        return create_login_graph(logins)

    @classmethod
    def get_priv_users(cls, target_machines, logins):
        """Get set of users / credentials who can access target machines."""
        logins = logins[logins[LoginColumns.DST].isin(target_machines)]
        return set(logins[LoginColumns.USER].drop_duplicates())

    @classmethod
    def get_paths_to_priv_users(cls, start_src, target_users, logins, login_graph=None):
        """Get set of users / credentials who can access target machines.

        Args:
            start_src: (str) hostname of initial foothold machine
            target_dsts: set of str's (hostnames of valuable machines)
            logins: pd.DataFrame of lgins
        """
        # Remove spurious logins + logins into clients for BOTH
        # computing target users to compromise AND path to those compr. users
        logins = remove_spurious_logins(logins)
        logins = logins[logins[EnrichmentColumns.DST_CLIENT] == False]
        if login_graph is None:
            login_graph = cls.create_login_graph(logins)

        # Get the destinations that the target users log into
        compromise_dsts = set(
            logins[logins[LoginColumns.USER].isin(target_users)][LoginColumns.DST].drop_duplicates()
        )
        compromise_dsts = set([
            dst for dst in compromise_dsts if is_compromisable_host(dst)
        ])

        print("Computing all simple paths between src = {} and "
                 "each of the {} dst (samp: {}) where attacker can compromise priv user creds.".format(
            start_src, len(compromise_dsts), safe_rand_sample(compromise_dsts, 10)
        ))
        all_paths = flatten_list([
            nx.all_simple_paths(login_graph, start_src, dst, cutoff=cls.MAX_PATH_LEN)
            for dst in compromise_dsts
        ])
        print("{} paths of len <= {} to dst w/ priv user creds.\nSample: {}.\n".format(
            len(all_paths), cls.MAX_PATH_LEN, safe_rand_sample(all_paths, 3)
        ))
        return all_paths

    @classmethod
    def get_stealthy_paths(cls, start_src, target_dsts, logins, login_graph=None):
        """Get shortest paths between src and each of the target dsts.

        Args:
            start_src: (str) hostname of initial foothold machine
            target_dsts: set of str's (hostnames of valuable machines)
            logins: pd.DataFrame of lgins
        """
        if login_graph is None:
            login_graph = cls.create_login_graph(logins)

        # Prune target dsts to ensure that they exist in this login batch
        all_dst = logins[LoginColumns.DST].drop_duplicates()
        target_dsts = target_dsts.intersection(all_dst)

        print("Computing all simple paths between src = {} and each of the {} target dst ({}).".format(
            start_src, len(target_dsts), target_dsts
        ))
        all_paths = flatten_list([
            nx.all_simple_paths(login_graph, start_src, dst, cutoff=cls.MAX_PATH_LEN)
            for dst in target_dsts
        ])
        print("{} paths of len <= {} to target dsts.\nSample: {}.\n".format(
            len(all_paths), cls.MAX_PATH_LEN, safe_rand_sample(all_paths, 3)
        ))
        return all_paths
