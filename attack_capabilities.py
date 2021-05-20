# This module contains code to track the attack's state and the attacker's
# resources/capabilities as the attack unfolds.

from data_types import *
from utils import *


class AttackerCapabilities(LoggingClass):
    """Encapsulate capabilities of the attacker during the attack."""
    # how long after user's last login are creds still compromisable?
    DEFAULT_CRED_EXPOSED_HRS = 24*7
    # attacker only knows history of machines they've moved onto
    KNOWLEDGE_LOCAL = "knowledge=local"
    # attacker knows full network topology
    KNOWLEDGE_GLOBAL = "knowledge=global"

    def __init__(self, knowledge, compromise_cred_hrs=None, verbose=True):
        """
        Args:
            knowledge: KNOWLEDGE_ class constant
        """
        super(AttackerCapabilities, self).__init__(verbose=verbose)
        self.knowledge = knowledge
        self.dst_per_compromised_user = dict()
        self.real_users = get_all_users()

        # How long after a user login are credentials vuln to compromise?
        self.compromise_cred_hrs = compromise_cred_hrs
        if self.compromise_cred_hrs is None:
            self.compromise_cred_hrs = self.DEFAULT_CRED_EXPOSED_HRS

        self.log("Attacker Capabilities set to: {}\t"
                 "cred exposure window={} hrs\n".format(
            self.knowledge, self.compromise_cred_hrs
        ))

    @classmethod
    def get_accessible_dst_for_user(cls, logins, user, protocol=None):
        """Get all of the dst a user has access to.

        Approximate by building a set of every dst that a user has accessed in
        a login across the entire dataset.
        """
        matching_logins = logins[
            (logins[LoginColumns.USER] == user)
        ]

        if protocol is None or not (LoginColumns.PROTOCOL in logins.columns):
            pass
        else:
            matching_logins = matching_logins[
                matching_logins[LoginColumns.PROTOCOL] == protocol
            ]

        # For now, accessible dst = dst that user has successfully accessed
        # this is a subset of user's actual permissions / accessible dst
        prior_dst = set(matching_logins[LoginColumns.DST].drop_duplicates())
        prior_dst = prior_dst - UNINTERESTING_DST

        return prior_dst

    def initialize_capabilities(self, start_state, logins):
        """Initialize capabilities."""
        self._update_candidate_dst(logins, start_state.start_user)

    def update_capabilities(self, new_time, new_dst, logins):
        """Update capability set: compromised cred set + dest set.

        Args:
            new_hop: pd.DataFrame of one row = new login event
            logins: pd.DataFrame of all logins we're considering
        """
        compromised_users = self._get_new_compromised_users(
            logins, new_time, new_dst)
        for (user, protocol) in compromised_users:
            self._update_candidate_dst(logins, user, protocol)

        compromised_users = set([u for (u, protocol) in compromised_users])
        return compromised_users

    def get_candidate_next_hops(self, attack_history):
        """Generate all possible movement hops.

        Args:
            attack_history: data_types.AttackHistory object
        Returns:
            list of [AttackNextHop namedtuple's]
        """
        candidate_hops = []
        candidate_srcs = self._get_candidate_src(attack_history)
        self.log("Candidate Hops: Candidate src = {}".format(candidate_srcs))

        next_hops = flatten_list([
            [AttackNextHop(src, dst, user) for src in candidate_srcs]
            for (user, dst) in self._get_candidate_user_dst()
        ])

        self.log("Candidate Hops: {} possible hops generated".format(len(next_hops)))
        return next_hops

    def _get_candidate_src(self, attack_history):
        """HELPER Method: Get candidate src of next hops = all visited machines."""
        return attack_history.visited_dst

    def _get_candidate_user_dst(self):
        """HELPER Method: Get accessible pairs of (user, dst) moves."""
        user_and_dst_pairs = flatten_list([
            [(user, dst) for dst in self.dst_per_compromised_user[user]]
            for user in self.dst_per_compromised_user
        ])
        self.log("Candidate Hops: {} candidate (user, dst) pairs".format(
                 len(user_and_dst_pairs)))

        return user_and_dst_pairs

    def _get_new_compromised_users(self, logins, time, host):
        """HELPER Method: Simulate an attacker compromising creds on a host.

        Returns:
            set([tuple(user, protocol)])
        """
        if host in NON_COMPROMISE_HOSTS or not is_compromisable_host(host):
            self.log(
                "Updating compromised creds:\tHost = {} is non-compromise-able"
                " host, so skipping cred compromise".format(host))
            return set([])

        # Identify all recent logins into the newly compromised host
        lower_bound = time - datetime.timedelta(hours=self.compromise_cred_hrs)
        vuln_logins = logins[
            (logins[LoginColumns.DST] == host) &
            (logins[LoginColumns.TIME] <= time) &
            (logins[LoginColumns.TIME] >= lower_bound)
        ]

        # Identify all users (potentially cached creds) that recently logged into host
        vuln_users = [
            (r[LoginColumns.USER], r[LoginColumns.PROTOCOL]) for idx, r in
            vuln_logins[
                [LoginColumns.USER, LoginColumns.PROTOCOL]
            ].drop_duplicates().iterrows()
        ]

        # 'Compromise' all real usernames
        compromised_users = set([
            (u, protocol) for (u, protocol) in vuln_users if u in self.real_users])
        self.log("Updating compromised creds:\t"
                 "Host = {} had {} users login within past {} hours.\n"
                 "Compromised (real) user set = {}".format(
                     host, len(vuln_users),
                     self.compromise_cred_hrs, compromised_users
        ))

        return compromised_users

    def _update_candidate_dst(self, logins, user, protocol=None):
        """HELPER Method: Update set of available dst attacker can move to."""
        if user in self.dst_per_compromised_user:
            # Save computation: we can ignore updating dst set for the
            return

        # Identify the dst that the user (credentials) prev accessed = candidate dst
        prior_dst = self.get_accessible_dst_for_user(logins, user, protocol=protocol)

        # Record what dst the user's creds provide access to
        self.dst_per_compromised_user[user] = \
            prior_dst | self.dst_per_compromised_user.get(user, set([]))

        self.log("Updating candidate dst with {} dst "
                 "(sample: {}) for compromised user = {}.\n".format(
            len(prior_dst), safe_rand_sample(prior_dst, 5), user
        ))
