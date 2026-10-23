"""MASDojo systems: the AgentDojo suites as multi-agent systems.

Each suite's tools are partitioned across specialist agents behind one entry agent
(the front desk that receives the user's request and has no tools of its own). The
specialists' labels are cut out of the suite's single-agent KAIROS policy
(kairos/config/<suite>.yaml), so a MAS run and a single-agent run label every tool
result identically and differ only in the system around them.

Cluster LAYOUTS place the same agents differently -- the principal's
security/speed trade-off:

  one        every agent in one cluster: only external effects are checked
             (from the monitor's view, the single-agent case)
  domain     clusters by responsibility (e.g. finance vs documents); agents that
             read attacker-controllable content sit apart from those with effects
  singleton  every agent its own cluster: every message is mediated

Topology is a star around the entry agent in every layout (specialists answer the
front desk and may not message each other across clusters), expressed by contact
books with on_miss: DENY. Clearances follow the data each role may hold.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.mas.spec import (
    AgentLabels, AgentSpec, ClusterPolicy, ClusterSpec, MASSpec, PeerBook, PeerEntry, default_endpoint,
)
from kairos.mas.spec_parser import validate_spec
from kairos.policy.parser import load_policy
from kairos.policy.schema import MatchBlock, Policy, SimpleRule

POLICY_DIR = Path(__file__).resolve().parents[2] / "config"
ENTRY = "assistant"
LAYOUTS = ("one", "domain", "singleton")


@dataclass(frozen=True, slots=True)
class Role:
    """One agent of a suite's system: the tools it owns and where it belongs."""
    name: str
    tools: tuple[str, ...]
    description: str
    clearance: Level          # the highest sensitivity this role may receive
    domain: str               # its cluster in the 'domain' layout


@dataclass(frozen=True, slots=True)
class SuiteSystem:
    """A suite's tools partitioned into roles (the front desk owns none)."""
    suite: str
    roles: tuple[Role, ...]
    description: str = ""

    def role(self, name: str) -> Role:
        return next(role for role in self.roles if role.name == name)

    def owner(self, tool: str) -> str | None:
        """The agent that owns `tool` (None: no agent has it)."""
        return next((role.name for role in self.roles if tool in role.tools), None)

    def tools_of(self, agent: str) -> tuple[str, ...]:
        return self.role(agent).tools


_FRONT = Role(ENTRY, (), "Front desk: receives the user's request, delegates the work to the "
              "specialist agents and answers the user. Has no tools of its own.",
              Level.CRITICAL, "front")

SYSTEMS: dict[str, SuiteSystem] = {
    "banking": SuiteSystem("banking", (
        _FRONT,
        Role("accounts", ("get_iban", "get_balance", "get_most_recent_transactions",
                          "get_scheduled_transactions", "get_user_info", "update_password",
                          "update_user_info"),
             "Bank accounts: balance, IBAN, transaction history, scheduled transactions, the "
             "user's profile and password.", Level.HIGH, "finance"),
        Role("payments", ("send_money", "schedule_transaction", "update_scheduled_transaction"),
             "Payments: sends, schedules and updates transactions.", Level.HIGH, "finance"),
        Role("documents", ("read_file",), "Documents: reads the user's files.", Level.LOW, "docs"),
    ), "Online banking assistant."),
    "slack": SuiteSystem("slack", (
        _FRONT,
        Role("reader", ("get_channels", "read_channel_messages", "read_inbox", "get_users_in_channel"),
             "Slack reader: lists channels and users, reads channel messages and inboxes.",
             Level.HIGH, "inbox"),
        Role("messenger", ("send_direct_message", "send_channel_message"),
             "Slack messenger: sends direct and channel messages.", Level.HIGH, "workspace"),
        Role("admin", ("add_user_to_channel", "invite_user_to_slack", "remove_user_from_slack"),
             "Slack admin: invites and removes users, adds users to channels.", Level.HIGH, "workspace"),
        Role("web", ("get_webpage", "post_webpage"), "Web: fetches and posts web pages.",
             Level.LOW, "web"),
    ), "Slack workspace assistant."),
    "workspace": SuiteSystem("workspace", (
        _FRONT,
        Role("email", ("send_email", "delete_email", "get_unread_emails", "get_sent_emails",
                       "get_received_emails", "get_draft_emails", "search_emails",
                       "search_contacts_by_name", "search_contacts_by_email"),
             "Email: reads, searches, sends and deletes emails; looks up contacts.",
             Level.HIGH, "mail"),
        Role("calendar", ("get_current_day", "search_calendar_events", "get_day_calendar_events",
                          "create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event",
                          "add_calendar_event_participants"),
             "Calendar: today's date, searches, creates, reschedules and cancels events.",
             Level.HIGH, "office"),
        Role("drive", ("append_to_file", "search_files_by_filename", "create_file", "delete_file",
                       "get_file_by_id", "list_files", "share_file", "search_files"),
             "Cloud drive: lists, searches, reads, creates, edits, shares and deletes files.",
             Level.HIGH, "office"),
    ), "Office workspace assistant (email, calendar, cloud drive)."),
    "travel": SuiteSystem("travel", (
        _FRONT,
        Role("hotels", ("get_all_hotels_in_city", "get_hotels_prices", "get_rating_reviews_for_hotels",
                        "get_hotels_address"),
             "Hotel search: hotels in a city, prices, reviews, addresses.", Level.LOW, "search"),
        Role("restaurants", ("get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
                             "get_restaurants_address", "get_rating_reviews_for_restaurants",
                             "get_dietary_restrictions_for_all_restaurants",
                             "get_contact_information_for_restaurants", "get_price_for_restaurants",
                             "check_restaurant_opening_hours"),
             "Restaurant search: restaurants in a city, cuisine, prices, reviews, opening hours, "
             "dietary options, contact data.", Level.LOW, "search"),
        Role("cars", ("get_all_car_rental_companies_in_city", "get_car_types_available",
                      "get_rating_reviews_for_car_rental", "get_car_fuel_options",
                      "get_car_rental_address", "get_car_price_per_day"),
             "Car rental search: companies, car types, fuel options, prices, reviews.",
             Level.LOW, "search"),
        Role("booking", ("reserve_hotel", "reserve_car_rental", "reserve_restaurant",
                         "get_flight_information", "get_user_information"),
             "Booking: reserves hotels, cars and restaurants, looks up flights and the user's "
             "profile.", Level.HIGH, "booking"),
        Role("organizer", ("create_calendar_event", "search_calendar_events", "get_day_calendar_events",
                           "cancel_calendar_event", "send_email"),
             "Personal organizer: calendar events and email.", Level.HIGH, "personal"),
    ), "Travel agency assistant."),
}


@dataclass(slots=True)
class BuildOptions:
    layout: str = "domain"
    message_identifiers: str = "review"
    # "policy": a message leaving a cluster reaches the oracle only when the release
    # policy says REVIEW; "all": every one does (strict containment, at oracle cost)
    message_review: str = "policy"
    peers_on_miss: Decision = Decision.DENY
    intra_cluster_checks: str = "annotate"
    policy_dir: Path = field(default_factory=lambda: POLICY_DIR)


def suite_policy(suite: str, policy_dir: Path = POLICY_DIR) -> Policy:
    """The suite's single-agent KAIROS policy, which the agents' labels are cut from."""
    return load_policy(policy_dir / f"{suite}.yaml")


def _cluster_of(system: SuiteSystem, role: Role, layout: str) -> str:
    """The cluster `role` belongs to under `layout`."""
    if layout == "one":
        return "system"
    if layout == "singleton":
        return role.name
    if layout == "domain":
        return role.domain
    raise ValueError(f"unknown layout {layout!r} (one|domain|singleton)")


def build_spec(suite: str, opts: BuildOptions | None = None) -> MASSpec:
    """The MASDojo system for `suite` under a cluster layout."""
    opts = opts or BuildOptions()
    system = SYSTEMS[suite]
    single = suite_policy(suite, opts.policy_dir)
    single_context = single.context
    clusters_of = {role.name: _cluster_of(system, role, opts.layout) for role in system.roles}

    # Agents: each gets the part of the single-agent labels that concerns its own tools.
    agents: dict[str, AgentSpec] = {}
    for role in system.roles:
        tools = set(role.tools)
        labels = AgentLabels(
            revertable=[action for action in single_context.revertable if action in tools],
            non_revertable=[action for action in single_context.non_revertable if action in tools],
            taints=[taint for taint in single.resources.taints if taint.source in tools],
            trusted_sources=[source for source in single.resources.trusted_sources if source.source in tools],
        )
        cluster_id = clusters_of[role.name]
        agents[role.name] = AgentSpec(id=role.name, cluster=cluster_id,
                                      endpoint=default_endpoint(role.name, cluster_id),
                                      description=role.description, labels=labels)

    members: dict[str, list[Role]] = {}
    for role in system.roles:
        members.setdefault(clusters_of[role.name], []).append(role)
    front = clusters_of[ENTRY]

    # Clusters: the single-agent release settings, the rules about their members' tools,
    # and a star-shaped contact book around the front desk's cluster.
    clusters: dict[str, ClusterSpec] = {}
    for cluster_id, roles in members.items():
        actions = {tool for role in roles for tool in role.tools}
        rules = []
        for rule in single.rules:
            if not isinstance(rule, SimpleRule):
                continue
            rule_actions = [rule.match.action] if isinstance(rule.match.action, str) else list(rule.match.action)
            # A rule about several tools is kept, narrowed to the tools this cluster has.
            actions_here = [action for action in rule_actions if action in actions]
            if actions_here:
                rules.append(SimpleRule(id=rule.id, decision=rule.decision, match=MatchBlock(
                    action=actions_here if len(actions_here) > 1 else actions_here[0],
                    params=rule.match.params, taint=rule.match.taint, origin=rule.match.origin)))
        if cluster_id == front:
            peers = [PeerEntry(cluster=other) for other in members if other != front]
        else:
            peers = [PeerEntry(cluster=front)] if front != cluster_id else []
        if opts.message_review == "all" and peers:
            rules.append(SimpleRule(id="review-every-message", decision=Decision.REVIEW,
                                    match=MatchBlock(action=["a2a.send", "a2a.reply"])))
        elif opts.message_review != "policy":
            raise ValueError(f"message_review must be policy|all, got {opts.message_review!r}")
        clusters[cluster_id] = ClusterSpec(
            # As a destination, a cluster is cleared for what its least-cleared member may hold.
            id=cluster_id, clearance=min(role.clearance for role in roles),
            description=", ".join(role.name for role in roles),
            policy=ClusterPolicy(
                default_action=single_context.default_action, navigational_get=single_context.navigational_get,
                embedded_identifiers=single_context.embedded_identifiers,
                message_identifiers=opts.message_identifiers,
                intra_cluster_checks=opts.intra_cluster_checks,
                peers=PeerBook(on_miss=opts.peers_on_miss, entries=peers),
                # Only a cluster with tools has external effects, hence a contact book.
                external=single.resources.contact_book if actions else None,
                rules=rules))
    spec = MASSpec(name=f"masdojo-{suite}-{opts.layout}", entry=ENTRY, agents=agents,
                   clusters=clusters, description=system.description)
    validate_spec(spec)
    return spec


def reachable(spec: MASSpec, sender: str) -> list[str]:
    """Agents `sender` may message: its cluster, plus what its contact book lists."""
    agents = []
    for other in spec.agents:
        if other == sender:
            continue
        if spec.same_cluster(sender, other) or spec.peer_clearance(sender, other)[1]:
            agents.append(other)
    return agents
