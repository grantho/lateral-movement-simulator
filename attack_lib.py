# Main module for generating synthetic attack logins
# Invoke synthesize_attack(...) to generate a dataframe = one attack path.

# Author: Grant Ho, 2021

import datetime
import pandas as pd
import random

from attack_capabilities import *
from attack_goal import *
from attack_stealth import *
from data_types import *
from login_synthesis import LoginSynthesizer

#########################################
# Constants
#########################################

SCENARIO_GOALS = [
    ScenarioConstants.GOAL_EXPLORATION,
    ScenarioConstants.GOAL_SPREAD,
    ScenarioConstants.GOAL_TARGETED
]

SCENARIO_STEALTHS = [
    ScenarioConstants.STEALTH_NONE, ScenarioConstants.STEALTH_ENDPOINTS,
    ScenarioConstants.STEALTH_ACTIVE_CREDS, ScenarioConstants.STEALTH_FULL
]

NON_COMPROMISE_HOSTS = set([])
UNINTERESTING_DST = set([])

#########################################
# End-to-end Wrapper Method for running
#########################################


def synthesize_attack(logins, attack_config, start_dt=None):
    """Method to synthesize attack from scratch.

    Args:
        logins: pd.DataFrame : one login per row
        attack_config: attack_lib.AttackPathConfig object
        start_dt: datetime.datetime of earliest login to use
    Return:
        pd.DataFrame of synthesized attack logins
    """
    # Ensure logins have proper columns / fields
    columns = logins.columns
    assert(
        LoginColumns.TIME in columns and
        LoginColumns.SRC in columns and
        LoginColumns.USER in columns and
        LoginColumns.DST in columns and
        LoginColumns.DATASET in columns
    )

    # Restrict data set according to login type
    if attack_config.protocol == 'ssh':
        data = logins[
            logins[LoginColumns.DATASET].str.lower().str.contains('ssh')]
    elif attack_config.protocol == 'windows':
        data = logins[
            logins[LoginColumns.DATASET].str.lower().str.contains('windows')]
    else:
        data = logins
    print("Using {} {} logins for attack synthesis\n".format(
        len(data), attack_config.protocol))

    # Generate the attack
    attack_generator = AttackPathGenerator(
        attack_config.attack_goal,
        start_state=attack_config.start_state,
        attacker_knowledge=attack_config.attacker_knowledge,
        stealth=attack_config.attack_stealth,
        src_preference=attack_config.src_preference,
        src_history_hrs=attack_config.src_history_hrs,
        compromise_cred_hrs=attack_config.compromise_cred_hrs,
        active_cred_hrs=attack_config.active_cred_hrs,
        target_machines=attack_config.target_machines,
        start_dt=start_dt
    )
    attack = attack_generator.make_attack(data)

    return attack


def is_synthetic_attack_successful(attack_df):
    """Attack is unsuccessful if it fails to switch to new user credentials."""
    if attack_df is None or len(attack_df) == 0:
        return False
    users = attack_df[LoginColumns.USER].drop_duplicates()
    return len(users) >= 2


#########################################


class AttackPathGenerator(LoggingClass):
    """Generate diffferent types of lateral movement paths."""
    VERSION = 0

    def __init__(
        self, attack_goal, attacker_knowledge, stealth,
        start_state=None, compromise_cred_hrs=None,
        active_cred_hrs=None, src_history_hrs=None, src_preference=None,
        target_machines=set([]), verbose=True, start_dt=None
    ):
        """Initialize attack path generator.

        Args:
            attack_goal: goal constant from MovementGoal
            attacker_knowledge: knowledge constant from AttackerCapabilities
            stealth: constant from MovementStealth
            state_state: utils.AttackStart object
            compromise_cred_hrs: (int) # of hours where credentials can
                still be compromised after last user login
            active_cred_hrs: (int) # of hours that a detector uses to causally
                link two logins setting for stealthy attacks
            src_history_hrs: (int) # of hours for a machine's recent logins,
                that an attacker can mine to see stealthy prev-traversed edges
                they can make from a machine
            src_preference: SRC_PREF constant from MovementConstraints
            target_machines: set of high-value hostnames (strs)
                for targeted attacks
        """
        super(AttackPathGenerator, self).__init__(verbose=verbose)
        self.real_users = get_all_users()

        # randomly sample interarrival (seconds)
        # between [0, self.interarrival_window_hrs] for next attack hop
        self.interarrival_window_hrs = 2

        self.start_dt = start_dt
        self.attack_start = start_state
        self.attack_history = None
        self.attack_capabilities = AttackerCapabilities(
            attacker_knowledge, compromise_cred_hrs)
        self.attack_constraints = MovementConstraints(src_preference)
        self.attack_stealth = MovementStealth(
            stealth, active_cred_hrs=active_cred_hrs,
            src_history_hrs=src_history_hrs)
        self.attack_goal = MovementGoal(
            attack_goal, target_machines=target_machines)

    def make_attack(self, logins):
        """MAIN method to generate the attack login dataframe."""
        logins = self._preprocess_logins(logins)

        # Initialize starting hop
        self._initialize_start(logins)

        # Iteratively generate next hop until attack goal met, or attack
        # runs out of options
        while not self.attack_goal.is_attack_complete(self.attack_history):
            next_time, next_src, next_dst, next_user = self._get_next_hop(logins)

            if next_dst is None:
                # Terminate if there are no more machines to move to
                self.log("\nWARNING: Attack ran out of potential dst. Terminating!!!\n")
                break
            else:
                # Print progress info
                self.log("Selected next hop: "
                         "(next hop time = {}, src = {}, dst = {}, user = {}.".format(
                    next_time, next_src, next_dst, next_user
                ))

            # Synthesize a new login event given a
            # (1) starting machine, (2) user, (3) destination
            new_hop = LoginSynthesizer().synthesize_login(
                logins, next_time, next_src, next_dst, next_user)
            new_hop.loc[:, LoginColumns.ATTACK] = True

            # Make the lateral move to the new destination & update state
            self._make_next_hop(new_hop, logins)

        return self.attack_history.attack_path.reset_index(drop=True)

    def _preprocess_logins(self, logins):
        """HELPER Method: Preprocess logins for attack generation."""
        logins = logins[
            (logins[LoginColumns.TIME] >= self.start_dt)
        ]

        # Filter logins to only ones that involve real users
        logins = logins[logins[LoginColumns.USER].isin(self.real_users)]

        # Filter out logins from ignore-set machines

        # Add additional filtering that you would like to apply

        return logins

    def _engineer_attack_start(self, logins):
        """Engineer the attack start based on stealthiness to ensure success."""
        print("Engineering attack starting.\n")

        i = 0
        while self.attack_start is None and i < 100:
            i += 1
            try:
                # Engineer the attack starting state depending on specified type of attack
                if self.attack_stealth.stealth == MovementStealth.STEALTH_ACTIVE_CREDS:
                    self.attack_start = AttackStart(AttackStart.START_AMBIG_PATH)
                elif self.attack_stealth.stealth == MovementStealth.STEALTH_ENDPOINTS:
                    self.attack_start = AttackStart(AttackStart.START_LONG_PATH)
                elif self.attack_stealth.stealth == MovementStealth.STEALTH_FULL:
                    self.attack_start = AttackStart(AttackStart.START_STEALTH_PATH)
                else:
                    self.attack_start = AttackStart()
                self.attack_start.initialize(logins)
            except:
                self.attack_start = None
                print("Failed attack start generation: {}".format(i))


    def _initialize_start(self, logins):
        """HELPER Method: Select initial compromise start + time."""
        # Initialize attack start
        if self.attack_start is None:
            i = 0
            print("Randomized attack start.\n")
            self.attack_start = AttackStart()
            self.attack_start.initialize(logins)
        else:
            print("Pre-specified starting state given: {}\t{}\t{}".format(
                self.attack_start.start_time, self.attack_start.start_src,
                self.attack_start.start_user
            ))

        # Initialize the starting state to fill in any non-prespecified values
        self.attack_start.initialize(logins)

        # Initialize goals
        self.attack_goal.target_info.initialize(
            self.attack_start.start_src, self.attack_start.start_time, logins)

        # Populate attack history
        self.attack_history = AttackHistory(self.attack_start)

        # Initialize Attacker's Capabilities
        compromised_users = set([self.attack_start.start_user,])
        foothold = self.attack_start.start_src
        self.attack_capabilities.initialize_capabilities(self.attack_start, logins)
        self.attack_stealth.update_knowledge(
            self.attack_start.start_time, foothold, logins)
        self.attack_history.update_compromised_creds(foothold, compromised_users)
        self.attack_goal.update_progress(foothold, compromised_users)

    def _make_next_hop(self, new_hop, logins):
        """HELPER Method: Update state based on attack moving along next hop."""
        self.log("Moving with new attack edge:")
        self.log(list(new_hop[LOGIN_ANALYSIS_COLUMNS].itertuples(index=False))[0])

        new_time = new_hop[LoginColumns.TIME].iloc[0]
        new_dst = new_hop[LoginColumns.DST].iloc[0]

        compromised_users = self.attack_capabilities.update_capabilities(
            new_time, new_dst, logins)
        self.attack_stealth.update_knowledge(new_time, new_dst, logins)
        self.attack_history.add_new_hop(new_hop)
        self.attack_history.update_compromised_creds(new_dst, compromised_users)
        self.attack_goal.update_progress(new_dst, compromised_users)

    def _get_next_hop(self, logins):
        """HELPER Method: Select the next attack hop to make."""
        self.log("Generating attack hop #{}".format(self.attack_history.num_hops))

        # Generate next attack hop's move time
        next_interarrival = random.randint(1, 3600 * self.interarrival_window_hrs)
        next_time = (
            self.attack_history.last_move_time +
            datetime.timedelta(seconds=next_interarrival)
        )

        # Generate candidate set of next hops based on attacker capabilities & knowledge
        candidate_next_hops = self.attack_capabilities.get_candidate_next_hops(
            self.attack_history)

        # Constrain / prune candidate next hops depending on desired steathiness
        candidate_next_hops = self.attack_stealth.constrain_next_hops(
            candidate_next_hops, self.attack_history)

        # Constrain / prune candidate next hops based on domain knowledge + threat model
        candidate_next_hops = self.attack_constraints.constrain_next_hops(
            candidate_next_hops, self.attack_history)

        # Select the next hop based on attack goal's
        next_hop = self.attack_goal.select_next_hop(
            candidate_next_hops, self.attack_history, self.attack_capabilities)

        return (next_time, next_hop.src, next_hop.dst, next_hop.user)


#########################################
# Attack Configuration Details
#########################################


class AttackPathConfig(LoggingClass):
    """Encapsulate an attack path configuration."""
    def __init__(
        self, attack_goal, attacker_knowledge, stealth, protocol,
        start_state=None,
        src_preference=MovementConstraints.SRC_PREF_NONE,
        compromise_cred_hrs=AttackerCapabilities.DEFAULT_CRED_EXPOSED_HRS,
        active_cred_hrs=MovementStealth.ACTIVE_CRED_HRS,
        src_history_hrs=MovementStealth.DEFAULT_SRC_HISTORY_HRS,
        target_machines=set([])
    ):
        """Initialize attack path generator."""
        self.attack_goal = attack_goal
        self.attacker_knowledge = attacker_knowledge
        self.attack_stealth = stealth
        self.protocol = protocol

        self.start_state = start_state
        self.src_preference = src_preference
        self.compromise_cred_hrs = compromise_cred_hrs
        self.active_cred_hrs = active_cred_hrs
        self.src_history_hrs = src_history_hrs
        self.target_machines = target_machines

    def get_file_suffix(self):
        """Get suffix that describes this attack's configuration."""
        suffix = ".{}.{}.{}.protocol={}.df"
        suffix = suffix.format(
            self.attack_goal, self.attack_stealth,
            self.attacker_knowledge, self.protocol
        )
        return suffix

    def __str__(self):
        """Return string representation of attack config."""
        if self.start_state:
            start_str = "AttackStart: time = {}, src = {}, user = {}, engineering = {}.".format(
                self.start_state.start_time, self.start_state.start_src,
                self.start_state.start_user, self.start_state.start_strategy
            )
        else:
            start_str = "AttackStart: None specified."

        main_str = ("AttackGoal: {}.\tAttackerKnowledge: {}.\tAttackStealth: {}."
                    "\tLoginProtocol: {}\tSourcePref: {}.\tTarget machines: {}".format(
            self.attack_goal, self.attacker_knowledge, self.attack_stealth,
            self.protocol, self.src_preference, self.target_machines
        ))

        auxil_str = (
            "Cred compromise exposure window: {} hrs."
            "\tActive cred window: {} hrs."
            "\tSrc-Dst history window: {} hrs."
        ).format(self.compromise_creds_hrs, self.active_cred_hrs, self.src_history_hrs)

        final_str = "{}\n{}\n{}".format(start_str, main_str, auxil_str)
        return final_str
