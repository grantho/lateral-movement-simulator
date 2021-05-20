# This module contains code to shape/prune the attack's path to conform to
# a desired stealthiness level, and/or network environment constraints.


from data_types import *
from utils import *


class MovementConstraints(LoggingClass):
    """Define constraints + pruning over movement paths."""
    SRC_PREF_NONE = "src_pref=none"
    SRC_PREF_FOOTHOLD = "src_pref=foothold"
    SRC_PREF_SERVER = "src_pref=server"
    SRC_PREF_CRED_SWITCH_AT_SERVER = "src_pref=cred-switch-at-server"

    MANAGEMENT_MACHINE = '-'  # machines to ignore during attack generation

    def __init__(self, src_preference=None, verbose=True):
        """
        Args:
            src_preference: SRC_PREF constant from MovementConstraints
        """
        super(MovementConstraints, self).__init__(verbose=verbose)
        self.src_preference = src_preference
        if self.src_preference is None:
            self.src_preference = self.SRC_PREF_NONE

    def constrain_next_hops(self, next_hops, attack_history):
        """Prune / constrain hops based on threat model.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        next_hops = self._remove_invalid_user_dst_hops(next_hops, attack_history)
        next_hops = self._handle_jump_host_src(next_hops, attack_history)
        next_hops = self._apply_src_preference(next_hops, attack_history)

        return next_hops

    def _remove_invalid_user_dst_hops(self, next_hops, attack_history):
        """HELPER Method: Remove hops to dst's accessible to start user,
                          but use another user's creds to access.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        start_user = attack_history.get_start_user()
        accessible_dst_from_start = attack_history.get_start_accessible_dst()
        next_hops = [
            hop for hop in next_hops if not(
                hop.user != start_user and hop.dst in accessible_dst_from_start
            )
        ]

        # Do not allow credential switch into a bastion machine
        # added Oct 12, 2020
        next_hops = [
            hop for hop in next_hops if not(
                is_server_jump_host(hop.dst) and hop.user != start_user
            )
        ]

        self.log("Path Constraints: {} hops after removing invalid user-dst's".format(
            len(next_hops)
        ))
        return next_hops

    def _handle_jump_host_src(self, next_hops, attack_history):
        """HELPER Method: If attack is on a jump host src, force cred continuity.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        cur_machine = attack_history.get_current_machine()
        self.log("Path Constraints: currently on host = {}. "
                 "Pruning any potential bastion paths accordingly.".format(
                  cur_machine))
        if is_server_jump_host(cur_machine):
            # If we're on a bastion node, then the next hop MUST move from bastion
            # w/ user continuity
            next_hops = [
                hop for hop in next_hops if (
                    hop.src == cur_machine and
                    hop.user == attack_history.get_current_user()
                )
            ]
            self.log("Path Constraints: currently on a jump host = {}, "
                     "so restricting to {} hops from bastion w/ continuity.".format(
                cur_machine, len(next_hops)
            ))
        else:
            # if we're NOT on a bastion node, then none of the candidate next src's
            # can be the bastion node
            next_hops = [
                hop for hop in next_hops
                if not is_server_jump_host(hop.src)
            ]
            self.log("Path Constraints: {} hops after removing any that "
                     "start from a bastion (since NOT on bastion).".format(
                      len(next_hops)))

        return next_hops

    def _apply_src_preference(self, next_hops, attack_history):
        """HELPER Method: Apply attacker movement pref for particular src."""
        foothold = attack_history.get_start_src()
        cur_machine = attack_history.get_current_machine()
        cur_user = attack_history.get_current_user()

        if self.src_preference == self.SRC_PREF_FOOTHOLD:
            # Return early if we're moving from clients / footholds
            next_hops = [hop for hop in next_hops if hop.src == foothold]
            return next_hops

        if self.src_preference == self.SRC_PREF_SERVER:
            # Move from any server OR allow any movement if we're continuing w/ current user
            next_hops = [
                hop for hop in next_hops if (
                    hop.user == cur_user or hop.src != foothold
                )]
        elif self.src_preference == self.SRC_PREF_CRED_SWITCH_AT_SERVER:
            # Viable next hops either (1) hops that do NOT switch from cur user
            # OR (2) hops that DO switch and occur from src != foothold
            next_hops = [
                hop for hop in next_hops if (
                    hop.user == cur_user or
                    (hop.user != cur_user and hop.src != foothold)
                )]

        # If movement happens from a server, ensure that we only switch to
        # using new creds on servers where we could compromise creds on
        next_hops = [
            hop for hop in next_hops if (
                hop.user == cur_user or
                hop.user in attack_history.compromised_creds_per_dst.get(hop.src, [])
            )
        ]

        return next_hops


class MovementStealth(MovementConstraints):
    """Define movement's stealthiness and next hop pruning."""
    # related to particular detector: time window to confuse our path inference engine
    ACTIVE_CRED_HRS = 24
    # the length of prior history where an attacker can see what logins have
    # prev been made from a src machine (for stealthy edge movement)
    DEFAULT_SRC_HISTORY_HRS = 24 * 31

    STEALTH_NONE = ScenarioConstants.STEALTH_NONE
    STEALTH_ENDPOINTS = ScenarioConstants.STEALTH_ENDPOINTS
    STEALTH_ACTIVE_CREDS = ScenarioConstants.STEALTH_ACTIVE_CREDS
    STEALTH_FULL = ScenarioConstants.STEALTH_FULL

    def __init__(
        self, stealth, active_cred_hrs=None, src_history_hrs=None,
        src_pref=MovementConstraints.SRC_PREF_NONE, verbose=True
    ):
        """
        Args:
            stealth: STEALTH_ class constant
            active_cred_hrs: (int) # of hours that a detector uses to causally
                link two logins setting for stealthy attacks
            src_history_hrs: (int) # of hours for a machine's recent logins,
                that an attacker can mine to see stealthy prev-traversed edges
                they can make from a machine
            src_preference: SRC_PREF constant from MovementConstraints
        """
        super(MovementStealth, self).__init__(
            src_preference=src_pref, verbose=verbose)
        self.stealth = stealth

        # State for opportunistic (edge cautiousness) stealthiness
        self.last_time_src_dst = dict()
        self.last_time_src_dst_user = dict()
        self.src_history_hrs = src_history_hrs
        if not self.src_history_hrs:
            self.src_history_hrs = self.DEFAULT_SRC_HISTORY_HRS

        # State for active credential switching stealthiness
        self.last_active_machine_user = dict()
        self.active_cred_hrs = active_cred_hrs
        if not self.active_cred_hrs:
            self.active_cred_hrs = self.ACTIVE_CRED_HRS

        self.log("Movement Stealthiness: {}\tactive cred window={} hrs\t"
                 "src preference = {}\n".format(
            self.stealth, self.active_cred_hrs, src_pref
        ))

    def constrain_next_hops(self, next_hops, attack_history):
        """Prune hops to those that fit stealthiness.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        print("Attack Stealthiness: {} candidate hops prior to constraints".format(
              len(next_hops)))
        next_hops = self._remove_visited_dst(next_hops, attack_history)

        if self.stealth in [self.STEALTH_ACTIVE_CREDS, self.STEALTH_FULL]:
            # Constrain hops to allow for stealthy use of creds
            next_hops = self._constraint_to_active_user_on_src(next_hops, attack_history)

        if self.stealth in [self.STEALTH_ENDPOINTS, self.STEALTH_FULL]:
            # Constrain hops to only traverses edges that benign users recently did
            next_hops = self._constraint_to_prev_src_dst(next_hops, attack_history)

        return next_hops

    def update_knowledge(self, new_time, new_dst, logins):
        """Update steathiness state / environment knowledge.

        Args:
            new_time: datetime.datetime object
            new_dst: str (hostname)
            logins: pd.DataFrame
        """
        self._update_active_compromised_creds(new_time, new_dst, logins)
        self._update_src_dst_recent_history(new_time, new_dst, logins)

    def _remove_visited_dst(self, next_hops, attack_history):
        """HELPER Method: Remove hops from visited destinations.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        next_hops = [
            hop for hop in next_hops if hop.dst not in attack_history.get_visited_dst()
        ]
        self.log("Attack Stealthiness: {} candidate hops after removing visited dst".format(
            len(next_hops)
        ))
        return next_hops

    def _update_src_dst_recent_history(self, move_time, new_dst, logins):
        """HELPER Method: Get history of where this new dst machine has launched logins into."""
        min_time = move_time - datetime.timedelta(hours=self.src_history_hrs)
        recent_logins = logins[
            (logins[LoginColumns.TIME] >= min_time) &
            (logins[LoginColumns.TIME] <= move_time)
        ]

        # Identify the logins where the new_dst *initiated* logins (i.e., was the src)
        # the attacker will look at the new machine's login history to see where to move
        recent_dst = recent_logins[recent_logins[LoginColumns.SRC] == new_dst]
        last_time_per_src_dst = recent_logins.groupby(
            [LoginColumns.SRC, LoginColumns.DST])[LoginColumns.TIME].max().to_dict()

        self.last_time_src_dst.update(last_time_per_src_dst)
        self.log("Attack Stealthiness (update): new_dst = {} has recently launched "
                 "logins into {} subsequent dst machines".format(
            new_dst, len(last_time_per_src_dst)
        ))

        self.last_time_src_dst_user = recent_logins.groupby(
            [LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER])[LoginColumns.TIME].max().to_dict()


    def _constraint_to_prev_src_dst(self, next_hops, attack_history):
        """HELPER Method: Constrain next hops to only walk along edges that prev were successful.

        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        min_active_time = \
            attack_history.last_move_time - datetime.timedelta(hours=self.src_history_hrs)
        next_hops = [
            hop for hop in next_hops if (
                self.last_time_src_dst.get((hop.src, hop.dst)) is not None and
                self.last_time_src_dst.get((hop.src, hop.dst)) >= min_active_time
#                 hop.user == attack_history.get_current_user() or  # Removed on 8/2/2020
            )
        ]
        self.log("Attack Stealthiness: {} next hops that traverse "
                 "a prev successful src - dst edge (past {} hrs).".format(
            len(next_hops), self.src_history_hrs
        ))

        max_stealth_next_hops = [
            hop for hop in next_hops if (
                self.last_time_src_dst_user.get((hop.src, hop.dst, hop.user)) is not None and
                self.last_time_src_dst_user.get((hop.src, hop.dst, hop.user)) >= min_active_time
            )
        ]
        if len(max_stealth_next_hops) > 0:
            next_hops = max_stealth_next_hops
            self.log("Attack Stealthiness: {} next hops that traverse "
                     "a prev successful FULL <src, dst, user> edge (past {} hrs).".format(
                len(next_hops), self.src_history_hrs
            ))

        return next_hops

    def _update_active_compromised_creds(self, move_time, new_dst, logins):
        """HELPER Method: What credentials are active on a dst that attacker has moved onto."""
        past_time_thresh = \
            move_time - datetime.timedelta(hours=self.active_cred_hrs)
        active_cred_logins = logins[
            (logins[LoginColumns.DST] == new_dst) &
            (logins[LoginColumns.TIME] >= past_time_thresh) &
            (logins[LoginColumns.TIME] < move_time)
        ]

        # Track the last time a given cred was used to log *into* a machine
        # (i.e., last time a credential was active [cached] on a machine)
        last_time_per_machine_user = active_cred_logins.groupby(
            [LoginColumns.DST, LoginColumns.USER])[LoginColumns.TIME].max().to_dict()
        self.last_active_machine_user.update(last_time_per_machine_user)
        self.log("Attack Stealthiness (update): {} active creds on {} "
                 "(users w/ logins INTO dst within <= {} hrs)".format(
            len(last_time_per_machine_user), new_dst, self.active_cred_hrs
        ))

    def _constraint_to_active_user_on_src(self, next_hops, attack_history):
        """Constrain next hops to those that use an active cred set on src machine.

        User is active on src machine if either
        (1) user = current user conducting movement,
        (2) new user, but that user recently logged *into* the src
        (within/after) move time - active cred thresh


        Args:
            next_hops: list of [AttackNextHop namedtuple's]
            attack_history: data_types.AttackHistory object
        """
        min_active_time = \
            attack_history.last_move_time - datetime.timedelta(hours=self.active_cred_hrs)
        next_hops = [
            hop for hop in next_hops if (
                hop.user == attack_history.get_current_user() or
                (self.last_active_machine_user.get((hop.src, hop.user)) is not None and
                 self.last_active_machine_user.get((hop.src, hop.user)) >= min_active_time
                )
            )
        ]
        self.log("Attack Stealthiness: {} next hops that either continue "
                 "current user creds OR switch to creds that recently (<= {} hrs) logged into src".format(
            len(next_hops), self.active_cred_hrs
        ))
        return next_hops
