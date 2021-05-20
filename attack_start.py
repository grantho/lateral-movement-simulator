# This module contains code for encapsulating the starting parameters of
# an attack.


import datetime
import random

from data_types import *
from utils import *

def get_viable_start_users(logins, target_dsts=set([])):
    """HELPER Method: Viable start users = non-sysadmins."""
    direct_access_users = set([])
    if target_dsts:
        direct_access_users = set(
            logins[logins[LoginColumns.DST].isin(target_dsts)][
              LoginColumns.USER
            ].drop_duplicates()
        )

    # Candidate users are real usernames without direct access and non-sysadmin
    real_users = get_all_users()
    candidate_users = real_users - direct_access_users
    sysadmins = get_sysadmin_users()
    candidate_users = candidate_users - sysadmins

    # Get all users across the logins
    logins = logins[~logins[LoginColumns.DST].isin(
        UNINTERESTING_DST | NON_COMPROMISE_HOSTS)
    ]
    login_users = set(logins[LoginColumns.USER].drop_duplicates())

    return login_users.intersection(candidate_users)


class AttackStart(object):
    """Select the initial point of compromise."""
    MIN_START_DAYS = 14   # min age (days) for initially compromised user / machine
    RAND_START_OFFSET_SEC = 86400 * 5  # rand offset to choose for start time

    START_RANDOM = "start:random"
    START_GUARANTEE_RANDOM = "start:random:guaranteed-attack"
    # engineer the init compromise to ensure that attack
    # has access to machines with recently-active cred's
    START_AMBIG_PATH = "start:unclear-cred-switch-path"
    # engineer initial compromise to give attacker paths
    # >= 2 hops that have been successfully traversed
    START_LONG_PATH = "start:long-path-guaranteed"
    START_STEALTH_PATH = "start:stealth-path"

    def __init__(self, start_strategy=None, start_user=None, start_time=None, start_src=None):
        self.min_age = self.MIN_START_DAYS
        self.start_time = start_time
        self.start_src = start_src
        self.start_user = start_user
        self.start_accessible_dst = None
        self.target_dsts = set([])

        self.start_strategy = start_strategy
        if self.start_strategy is None:
            self.start_strategy = self.START_RANDOM

        # Track what new (credential, accessible dst) each start user has access to
        # The current method is fixed to one random accessible dst
        self.elevation_opportunities_per_start_user = None

    @classmethod
    def time_box_logins_for_user_src(cls, logins, start_user, start_src, min_time=None):
        """Bound the logins within user's activity on src."""
        if not min_time:
            min_time = logins[
                (logins[LoginColumns.SRC] == start_src) &
                (logins[LoginColumns.USER] == start_user)
            ][LoginColumns.TIME].min()

        max_time = logins[
            (logins[LoginColumns.SRC] == start_src) &
            (logins[LoginColumns.USER] == start_user)
        ][LoginColumns.TIME].max() + datetime.timedelta(days=7)

        logins = logins[
            (logins[LoginColumns.TIME] >= min_time) &
            (logins[LoginColumns.TIME] <= max_time)
        ]
        return logins

    def initialize(self, logins, target_dsts=set([])):
        """MAIN METHOD: Get the initial point of compromise + time."""
        self.target_dsts = target_dsts

        if not all ([v is not None for v in [self.start_time, self.start_src, self.start_user]]):
            logins = self._filter_logins_for_start(logins)

            self._select_start_user(logins)
            self._select_start_src(logins)
            self._select_start_time(logins)

        print("Initial time, src, user selected: (time = {}, src = {}, user = {})".format(
            self.start_time, self.start_src, self.start_user
        ))
        print_divider()

        self.start_accessible_dst = \
            AttackerCapabilities.get_accessible_dst_for_user(logins, self.start_user)

    def _select_start_user(self, logins):
        """Select starting user."""
        if self.start_user:
            print("Starting user PRE-set to = {}".format(self.start_user))
            return

        if self.start_strategy == self.START_RANDOM and not self.start_user:
            self._select_start_user_random(logins)
        elif self.start_strategy in [self.START_LONG_PATH, self.START_STEALTH_PATH]:
            self._select_start_user_guaranteed_long_path(logins)
        else:
            self._select_start_user_guaranteed_lm(logins)

    def _select_start_src(self, logins):
        """Get machine for corresponding compromised start user."""
        assert(self.start_user is not None or self.start_src is not None)
        if self.start_src:
            print("Starting src PRE-set to = {}".format(self.start_src))
        else:
            # Get client src for compromised user
            self.start_src = self._get_src_machine_for_user(self.start_user, logins)

    def _select_start_time(self, logins, min_time=None):
        """HELPER Method: Select starting attack time.

        Randomly select a real login time after the src's first appearance and
        then add a random offset (the random time can be from any src/user's login)
        """
        if self.start_time:
            print("Specific starting time set = {}".format(self.start_time))
            return

        # Select the attack starting time:
        # (make sure it's after the first login from the
        # randomly choosen attack starting src so that we have history for the src)
        logins = self.time_box_logins_for_user_src(
            logins, self.start_user, self.start_src, min_time=min_time)

        if self.start_strategy == self.START_RANDOM:
            self._select_start_time_random(logins)
        elif self.start_strategy in [self.START_AMBIG_PATH, self.START_STEALTH_PATH]:
            self._select_start_time_confusion_paths(logins)
        else:
            self._select_start_time_guaranteed_lm(logins)

    def _select_start_time_guaranteed_lm(self, logins):
        """Select a start time that guarantees ability to access new creds w/ new dst."""
        # Pick a random elevation user who could be compromised during LM
        assert(self.elevation_opportunities_per_start_user is not None)
        user_and_dst_elevations = self.elevation_opportunities_per_start_user[self.start_user]
        print("Start time: engineering to guarantee new cred access: opportunities: {} ({})".format(
            len(user_and_dst_elevations), user_and_dst_elevations
        ))
        other_user, key_dst = random.sample(user_and_dst_elevations, 1)[0]

        # Winnow initial login to ensure that compromise happens after a vuln login
        # by the random elevation user
        logins = logins[
            (logins[LoginColumns.USER] == other_user) &
            (logins[LoginColumns.DST] == key_dst)
        ]
        print("Start time: {} logins that leave rand elevation user ({}) exposed on {}".format(
            len(logins), other_user, key_dst
        ))

        assert(len(logins) > 0)
        self._select_start_time_random(logins)

    def _select_start_time_confusion_paths(self, logins):
        """HELPER Method:

        Select a random start time for an attack that ensures ambig
        cred-switching paths during attack.

        Idea:
            1) Find a target server where ambig cred switching will happen
            2) Find a login by another user into this target server
            3) Pick a random time (with cred-switching window) after this login as the attack start
        """
        if self.start_time:
            print("Specific starting time set = {}".format(self.start_time))
            return

        # Find servers with multiple users who login
        real_users = get_all_users()
        users_per_dst = df_to_grouped_dict(
            logins, LoginColumns.DST, LoginColumns.USER, set)
        users_per_dst = {
            dst: set([u for u in users_per_dst[dst] if u and u in real_users])
            for dst in users_per_dst
            if len(users_per_dst[dst]) > 2 and not is_server_jump_host(dst)
        }

        # Identify shared servers w/ multi-user login per user where ambig causal path with traverse
        viable_intermediates = [dst for dst in users_per_dst if self.start_user in users_per_dst[dst]]
        confusion_server = random.sample(viable_intermediates, 1)[0]
        print("Selected {} as cred-switching server from {} potential machines.".format(
            confusion_server, len(viable_intermediates)
        ))

        # Find another user that has logged into the target confusion server
        other_users = users_per_dst[confusion_server] - set([self.start_user,])
        rand_other_user = random.sample(other_users, 1)[0]
        print("Selected {} as potential cred-switch user from {} potential other users.".format(
            rand_other_user, len(other_users)
        ))

        # Pick a random time that this other user has logged into the target server
        # (and ensure that it's after the initial foothold is active)
        min_time = logins[logins[LoginColumns.SRC] == self.start_src][LoginColumns.TIME].min()
        confusion_logins = logins[
            (logins[LoginColumns.DST] == confusion_server) &
            (logins[LoginColumns.USER] == rand_other_user) &
            (logins[LoginColumns.TIME] >= min_time)
        ]
        target_login = confusion_logins.sample(1)
        self.start_time = target_login[LoginColumns.TIME].iloc[0]
        target_login = list(target_login[
            [LoginColumns.TIME,] + LOGIN_EDGE_COLS].itertuples(index=False))[0]
        print("Selected benign login: {}\n(from {} candidates logins "
              "as ambig inbound login to attack inbound login".format(
            target_login, len(confusion_logins)
        ))
        print_small_divider()

        # Add a random offset for attack time that is within the cred-switching window
        rand_seconds = random.randint(1, 86400 / 2)  # pick a random time offset within 0s - 1/2 day
        self.start_time = self.start_time + datetime.timedelta(seconds=rand_seconds)

    def _select_start_time_random(self, logins):
        """Select a random start time after a min threshold"""
        self.start_time = logins[LoginColumns.TIME].sample(1)
        self.start_time = self.start_time.iloc[0]  # pick a random login time after first src use

        # pick a random time offset within 0s - 1day
        rand_seconds = random.randint(1, self.RAND_START_OFFSET_SEC)
        self.start_time = self.start_time + datetime.timedelta(seconds=rand_seconds)

    def _select_start_user_guaranteed_long_path(self, logins):
        """HELPER Method: Constrained start generation to gurantee attacker has long path option.

        Find intermediate servers where users login to the machine & launch logins from the machine,
        as well as the min

        Need to find a time where (1) user exists, (2) user has prev accessed an intermediate dst,
        # (3) that intermeidate dst has prev accessed another machine
        """
        print("Engineering start to ensure initial victim has long path potential.")
        print_small_divider()

        # Select a starting user who has access to an intermediate dest
        # and who fits criteria for guaranteed LM (i.e., one of servers they have access to )
        min_time_per_intermediate_dsts = self._get_intermediate_dsts(logins)
        vuln_intermediates = set(min_time_per_intermediate_dsts.keys())
        print("Start user selection: engineering to ensure that start user "
              "has access to one of {} intermediate dst: {}\n".format(
                len(vuln_intermediates), vuln_intermediates)
             )

        self._select_start_user_guaranteed_lm(logins, vuln_intermediates=vuln_intermediates)

    def _select_start_user_guaranteed_lm(self, logins, vuln_intermediates=set([])):
        """Get a map of what machines + elevated users each user can access.

        Returns:
            dictionary: {user -> set([(dst machine, other user w/ greater access)])}
        """
        # Identify which dst users can access
        dst_per_user = df_to_grouped_dict(
            logins, LoginColumns.USER, LoginColumns.DST, set)

        # Get dst w/ multiple users
        users_per_dst = df_to_grouped_dict(
            logins, LoginColumns.DST, LoginColumns.USER, set)
        multi_user_dst = [dst for dst in users_per_dst if len(users_per_dst[dst]) > 1]

        # Get viable dst that can server as compromise points
        multi_user_dst = set([dst for dst in multi_user_dst if is_compromisable_host(dst)])
        if vuln_intermediates:
            multi_user_dst = multi_user_dst.intersection(vuln_intermediates)

        if self.start_user:
            # If start user pre-set, initialize the elevation opportunities to ensure
            # that viable time is selected
            viable_dst = set(logins[
                logins[LoginColumns.USER] == self.start_user][LoginColumns.DST])
            multi_user_dst = multi_user_dst.intersection(viable_dst)

        print("Selecting start user w/ access to one of {} multi-user-dst's".format(len(multi_user_dst)))
        rand_dst = None
        viable_start_users = self._get_viable_start_users(logins)
        while len(multi_user_dst) > 0:
            # Pick a potential elevation dst
            rand_dst = random.sample(multi_user_dst, 1)[0]
            candidate_start_users = viable_start_users.intersection(users_per_dst[rand_dst])

            # Assess whether any users have ability to elevate their access
            # Map each potential starting user to a set of the elevation opportunities at this dst
            elevation_opportunities_per_start_user = {
                user: set([
                    (other_user, rand_dst) for other_user in users_per_dst[rand_dst]
                    if len(dst_per_user[other_user] - dst_per_user[user]) > 0
                ]) for user in candidate_start_users
            }
            elevation_opportunities_per_start_user = {
                user: elevation_opportunities_per_start_user[user]
                for user in elevation_opportunities_per_start_user
                if elevation_opportunities_per_start_user[user]
            }

            if len(elevation_opportunities_per_start_user) > 0:
                self.elevation_opportunities_per_start_user = \
                    elevation_opportunities_per_start_user
                break
            else:
                multi_user_dst.remove(rand_dst)

        print("Start user: engineering to ensure "
              "interesting LM cred-switching (available at dst = {})".format(rand_dst))
        self._select_start_user_random(
            logins, candidate_start_users=elevation_opportunities_per_start_user.keys())

    def _select_start_user_random(self, logins, candidate_start_users=None):
        """Select starting user from random."""
        # Starting compromise machine should be a client
        logins = logins[logins[EnrichmentColumns.SRC_CLIENT] == True]
        if self.start_time:
            logins = logins[
                (logins[LoginColumns.TIME] >= self.start_time - datetime.timedelta(hours=24)) &
                (logins[LoginColumns.TIME] <= self.start_time + datetime.timedelta(hours=24))
            ]

        # Pick a random starting victim / compromised user
        if not candidate_start_users:
            candidate_start_users = self._get_viable_start_users(logins)
        self.start_user = random.sample(candidate_start_users, 1)[0]
        print("Starting user: Randomly selected {} from {} viable start users".format(
            self.start_user, len(candidate_start_users)
        ))

    def _get_viable_start_users(self, logins):
        """HELPER Method: Viable start users = non-sysadmins."""
        return get_viable_start_users(logins, self.target_dsts)

    def _get_src_machine_for_user(self, user, logins):
        """Get src machine for user."""
        logins = logins[logins[EnrichmentColumns.SRC_CLIENT] == True]
        logins = logins[logins[LoginColumns.USER] == user]

        top_srcs = logins[LoginColumns.SRC].mode()
        for src in top_srcs:
            owners = logins[
                logins[LoginColumns.SRC] == src][EnrichmentColumns.SRC_OWNER]
            owners = owners.mode(dropna=True)
            if len(owners) > 0 and owners.iloc[0] == user:
                return src

        return top_srcs.iloc[0]

    def _get_intermediate_dsts(self, logins):
        """Get destinations that also launch logins"""
        min_time_per_dst = logins.groupby(
            LoginColumns.DST)[LoginColumns.TIME].min().reset_index(name=LoginColumns.TIME)
        min_time_per_dst = {
            r[LoginColumns.DST]: r[LoginColumns.TIME]
            for idx, r in min_time_per_dst.iterrows()
        }
        min_time_per_src = logins.groupby(
            LoginColumns.SRC)[LoginColumns.TIME].min().reset_index(name=LoginColumns.TIME)
        min_time_per_src = {
            r[LoginColumns.SRC]: r[LoginColumns.TIME]
            for idx, r in min_time_per_src.iterrows()
        }

        intermediate_dsts = [
            node for node in min_time_per_src if (
            not is_server_jump_host(node) and node in min_time_per_dst
        )]
        min_time_per_intermediate_dsts = {
            node: max(min_time_per_dst[node], min_time_per_src[node])
            for node in intermediate_dsts
        }
        print("{} dst machines are INTERMEDIARIES that have launched logins "
              "as srcs".format(len(min_time_per_intermediate_dsts)))
        return min_time_per_intermediate_dsts

    def _filter_logins_for_start(self, logins):
        """HELPER Method: Prune login set to suitable set for initial compromise.

        Filter down logins to
            (0) ensure that users can access non-terminate machines
            (1) uses a real username
            (2) not new machine or new users [1+ week old],
            (3) not sysadmin,
            (4) middle of dataset
        """
        # Ignore logins from terminal machines to ensure users can go interesting places
        avoid_dsts = UNINTERESTING_DST | NON_COMPROMISE_HOSTS
        logins = logins[~logins[LoginColumns.DST].isin(avoid_dsts)]

        # Ignore logins from non person usernames
        real_users = get_all_users()
        valid_logins = logins[
            logins[LoginColumns.USER].isin(real_users)
        ]
        # Don't allow a sysadmin to be the initial point of compromise
        sysadmins = get_sysadmin_users()
        valid_logins = valid_logins[
            ~valid_logins[LoginColumns.USER].isin(sysadmins)
        ]
        # Ignore logins from new machines / uesrs
        valid_logins = valid_logins[
            ~valid_logins[EnrichmentColumns.MACHINE_AGE].isnull() &
            (valid_logins[EnrichmentColumns.MACHINE_AGE] >= self.min_age * 86400) &
            ~valid_logins[EnrichmentColumns.USER_AGE].isnull() &
            (valid_logins[EnrichmentColumns.USER_AGE] >= self.min_age * 86400)
        ]
        print("{} candiate logins for initial attack state "
              "(non-sysadmin, real-user, and not-new)".format(
                  comma_num(len(valid_logins)))
             )

        # Pick a login from the middle of the dataset to ensure we have enough history for features
        min_time = logins[LoginColumns.TIME].min() + datetime.timedelta(weeks=2)
        max_time = logins[LoginColumns.TIME].max() - datetime.timedelta(weeks=1)
        valid_logins = valid_logins[
            (valid_logins[LoginColumns.TIME] >= min_time) &
            (valid_logins[LoginColumns.TIME] <= max_time)
        ]
        print(
            "{} candiate logins ({} users) after "
            "narrowing timeframe to middle of batch ({} - {})".format(
                comma_num(len(valid_logins)),
                len(valid_logins[LoginColumns.USER].drop_duplicates()),
                min_time, max_time
            )
        )

        return valid_logins
