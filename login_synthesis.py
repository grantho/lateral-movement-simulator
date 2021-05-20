# This module contains code to synthesize new login events.

import datetime
import pd

from data_types import *
from utils import *

LOGIN_ANALYSIS_COLUMNS = [
    LoginColumns.TIME, LoginColumns.SRC, LoginColumns.DST, LoginColumns.USER,
    EnrichmentColumns.SRC_OWNER, EnrichmentColumns.SRC_SUBNET,
    EnrichmentColumns.SRC_CLIENT,
]


class MovementLabeler(MovementTypes):
    """Class for labeling login movement types."""
    def __init__(self):
        self.col = LoginColumns.MOVEMENT_TYPE

    def label_movement_into_client(self, logins):
        """Label a login if client -> server (single hop)."""
        client_dst = (logins[EnrichmentColumns.DST_CLIENT] == True)
        logins.loc[client_dst, self.col] = self.MOVE_INTO_CLIENT
        return logins

    def label_movement_from_client(self, logins):
        """Label a login that goes into client (single hop)."""
        unassigned = logins[self.col].isnull()
        client_mask = (logins[EnrichmentColumns.SRC_CLIENT] == True)

        modify_mask = (unassigned & client_mask)
        logins.loc[modify_mask, self.col] = self.MOVE_FROM_CLIENT
        return logins

    def label_movement_from_server(self, logins):
        """Label a login from server -> server (paths)."""
        unassigned = logins[self.col].isnull()
        server_mask = (logins[EnrichmentColumns.SRC_CLIENT] == False)

        modify_mask = (unassigned & server_mask)
        logins.loc[modify_mask, self.col] = self.MOVE_FROM_SERVER
        return logins

    def label_movement(self, logins):
        """Label dataframe of logins."""
        if self.col not in logins.columns:
            logins[self.col] = np.nan

        # Set aside any logins that already have movement labels
        movement_types = set([
            self.MOVE_FROM_CLIENT, self.MOVE_INTO_CLIENT,
            self.MOVE_FROM_SERVER
        ])
        labeled_logins_mask = logins[self.col].isin(movement_types)
        labeled_logins = logins[labeled_logins_mask]

        unlabeled_logins = logins[~labeled_logins_mask]
        unlabeled_logins = self.label_movement_into_client(unlabeled_logins)
        unlabeled_logins = self.label_movement_from_client(unlabeled_logins)
        unlabeled_logins = self.label_movement_from_server(unlabeled_logins)

        return pd.concat([labeled_logins, unlabeled_logins], sort=False)


class LoginSynthesizer(object):
    """Class for creating an artificial login event.

    Abstraction: Given a <time, src, dst, user> of a fake login event to generate,
    create a fully-fleshed event with as much realistic metadata / enrichment attributes
    as possible (e.g., add the src host information, such as client vs. server, owner, etc.)
    and return a full-schema event for the fake login.
    """
    DATASET_ATTACK_SUCCESS = 'attack:success'

    def __init__(self, login_type=None):
        if not login_type:
            login_type = self.DATASET_ATTACK_SUCCESS

        self.login_type = login_type

    def log(self, msg):
        """Helper Method: Log message depending on verbose or not."""
        print(msg)

    def synthesize_login(self, logins, time, src, dst, user):
        """MAIN METHOD: Create a fake login tuple with realistic attributes.

        Args:
            logins: pd.DataFrame of real logins
            time: datetime.datetime object: time when the fake attack will occur
            src: (str) hostname of machine to launch the login from
            dst: (str) hostname of machine that login accesses
            user: (str) username / credentials to use in remote login
        Returns:
            pandas DataFrame (one row) that holds the fake login's information
        """
        # Try to find a real login that matches the <src, dst, user> we're synthesizing
        attack_df = logins[
            (logins[LoginColumns.SRC] == src) &
            (logins[LoginColumns.DST] == dst) &
            (logins[LoginColumns.USER] == user)
        ]

        if len(attack_df) > 0:
            # If the fake login has actually has occurred,
            # find the closest corresponding real login and copy over its information
            attack_df = self._get_closest_login(attack_df, time)
            self.log("Synthesizing login info:  Synthetic attack edge: "
                     "{} exists. Reusing.".format(
                attack_df.head(1)[LOGIN_ANALYSIS_COLUMNS].to_dict()
            ))
        else:
            # If the fake login's edge <src, dst, user> has never occurred,
            # construct a fake login event by mashing together metadata
            # from real logins that involved the src / dst / user separately
            closest_src, closest_user, closest_dst = self._get_synthetic_login_templates(
                logins, time, src, dst, user
            )
            self.log("Synthesizing login info: Constructing attack edge from SCRATCH:"
                  "\nsrc ({}) login: {}\ndst ({}) login: {}\nuser ({}) login: {}".format(
                      src, closest_src[LOGIN_ANALYSIS_COLUMNS].to_dict(),
                      dst, closest_dst[LOGIN_ANALYSIS_COLUMNS].to_dict(),
                      user, closest_user[LOGIN_ANALYSIS_COLUMNS].to_dict(),
            ))

            # Create a dummy event that we will overwrite with the mash-up of login events above
            # Goal = reuse the closest src login as the dummy event to fill in
            base_login = self._create_base_login_from_src(closest_src)
            if base_login is None:
                # However, we might have selected a src that's never launched logins,
                # in this case, take the dst login and do some extra work to format.
                base_login = self._create_base_login_from_dst(closest_dst, src)

            # Overwrite the dummy event's attributes with the mash-up of src/dst/user login events
            attack_df = self._merge_into_new_login(
                base_login, closest_src, closest_dst, closest_user)

        # Set the fake login's time to the specified time
        attack_df.loc[:, LoginColumns.TIME] = time
        attack_df.loc[:, LoginColumns.TIME] = pd.to_datetime(
            attack_df[LoginColumns.TIME]).copy()

        # Update the inbound login count to this src based on global history
        # This handles the case where the attacker moves to and launches logins from
        # a (src) machine that receives logins, but never launches them
        # (thus no src login will be found and the inbound days col will incorrectly be NaN)
        attack_df.loc[:, EnrichmentColumns.NUM_INBOUND_DAYS] = len(
            logins[logins[LoginColumns.DST] == src][DAY_COL].drop_duplicates()
        )

        # Set some final fields for the fake login event to make clear it's a fake / attack event
        attack_df = self._format_synthetic_login(attack_df)

        return attack_df

    def _get_closest_login(self, logins, cur_time):
        """HELPER Method: Get the real login closest to cur_time."""
        # Synthesize current attack based off of nearest / most recent
        # actual login edge
        interarrival_col = 'closest_interarrival'
        match = logins

        match[interarrival_col] = (match[LoginColumns.TIME] - cur_time).abs()
        match = match.sort_values(interarrival_col)
        match = match.head(1).copy().drop(columns=interarrival_col)
        return match

    def _get_synthetic_login_templates(self, logins, time, src, dst, user):
        """HELPER Method: Get real logins so we have info to fill in for the synthetic event.

        If the synthetic attack edge has not occurred,
        piece together info from logins that involve the src/dst/user
        of the synthetic login
        """
        closest_dst = self._get_closest_login(
            logins[logins[LoginColumns.DST] == dst], time)

        # Try to find a login with both the <src, user> to use a template
        closest_src = self._get_closest_login(
            logins[
                (logins[LoginColumns.SRC] == src) & (logins[LoginColumns.USER] == user)
            ], time
        )
        if len(closest_src) > 0:
            closest_user = closest_src
        else:
            print("Synthesizing login info: Unable to find a login with "
                  "<src={}, user={}>, so synthesizing "
                  "from disparate src, user, dst logins".format(src, user))
            closest_src = self._get_closest_login(
                logins[logins[LoginColumns.SRC] == src], time)
            closest_user = self._get_closest_login(
                logins[logins[LoginColumns.USER] == user], time)

        return closest_src, closest_user, closest_dst

    def _create_base_login_from_src(self, src_login):
        """HELPER Method: Synthesize a skeleton login event that has some basic information."""
        if src_login is None or len(src_login) == 0:
            return None

        base_login = src_login.copy()
        keep_cols = [
            LoginColumns.SRC, EnrichmentColumns.SRC_SUBNET,
            EnrichmentColumns.SRC_CLIENT, EnrichmentColumns.SRC_OWNER,
            EnrichmentColumns.MACHINE_EARLIEST_DATE, EnrichmentColumns.MACHINE_AGE,
            LoginColumns.DATASET
        ]

        for c in base_login.columns:
            if c not in keep_cols:
                base_login.loc[:, c] = np.nan

        return base_login

    def _create_base_login_from_dst(self, dst_login, src):
        """HELPER Method: Synthesize a skeleton login event that has some basic information."""
        base_login = dst_login.copy()

        # Replace the src info with the src we're synthesizing an attack from
        src_cols = [LoginColumns.SRC,]

        # Fill in the src information
        for c in src_cols:
            base_login.loc[:, c] = src

        # The only way the src doesn't have a login is if
        # the src is a server
        base_login.loc[:, EnrichmentColumns.SRC_CLIENT] = False
        keep_cols = src_cols + [EnrichmentColumns.SRC_CLIENT,]

        for c in base_login.columns:
            if c not in keep_cols:
                base_login.loc[:, c] = np.nan

        return base_login

    def _merge_into_new_login(self, base_login, src_login, dst_login, user_login):
        """HELPER Method: Fill in a skeleton event w/ info from relevant real logins."""
        attack = base_login

        # Replace the dst info fields
        for c in [
            LoginColumns.DST, LoginColumns.PROTOCOL,
            LoginColumns.DATASET, EnrichmentColumns.DST_CLIENT
        ]:
            attack.loc[:, c] = dst_login[c].tolist()[0]

        # Replace the user info fields
        for c in [
            LoginColumns.USER, EnrichmentColumns.USER_TEAM
        ]:
            attack.loc[:, c] = user_login[c].tolist()[0]

        # Set the age of the user to reflect age @ time of synthetic attack
        old_user_age = user_login[EnrichmentColumns.USER_AGE].tolist()[0]
        age_offset = (src_login[LoginColumns.TIME] - user_login[LoginColumns.TIME]).tolist()[0]
        if pd.isna(age_offset) or age_offset <= datetime.timedelta(seconds=0):
            age_offset = datetime.timedelta(seconds=0)
        attack.loc[:, EnrichmentColumns.USER_AGE] = old_user_age + age_offset.total_seconds()

        return attack

    def _format_synthetic_login(self, attack_df):
        """HELPER Method: Finalize some fields for the synthetic login."""
        attack = attack_df.copy()

        if len(attack[~attack[EnrichmentColumns.MACHINE_EARLIEST_DATE].isnull()]) > 0:
            attack.loc[:, EnrichmentColumns.MACHINE_AGE] = (
                attack[LoginColumns.TIME] - attack[EnrichmentColumns.MACHINE_EARLIEST_DATE]
            ).dt.total_seconds().copy()

            # In case the closest login is actually in future & earliest machine date has
            # been reset to account for new ownership
            mask_negative_age = attack[EnrichmentColumns.MACHINE_AGE] < 0
            attack.loc[mask_negative_age, EnrichmentColumns.MACHINE_AGE] = \
                attack.loc[mask_negative_age, EnrichmentColumns.USER_AGE].copy()

        # Label Movement type
        attack.loc[:, LoginColumns.MOVEMENT_TYPE] = np.nan  # need to reset movement label
        movement_labeler = MovementLabeler()
        attack = movement_labeler.label_movement(attack)

        attack.loc[:, LoginColumns.DATASET] = self.login_type

        return attack
