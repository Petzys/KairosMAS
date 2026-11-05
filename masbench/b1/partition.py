"""B1 agent split and tool annotations.

The split is MultiAgentDojo's ("Can CaMeLs talk?", Table I): per suite one tool-less orchestrator
that receives the user prompt, plus the sub-agents and tool counts of the table. The table gives
only the scope of each sub-agent; the tool-to-agent mapping below follows that scope and matches
every tool count of the table.

Tool annotations (`ToolSpec` fields) are facts about the tools, fixed before any run:
    (effect, reversible, external, impact, output_trust, output_sensitivity)
* external = the effect reaches a third party (money, messages, invitations, bookings, web).
* impact high = money movement, credentials and account data, data leaving the MAS (send,
  post, share), membership changes. Bookings, calendar edits and deletions are low.
* output_trust untrusted = output contains third-party content (received messages, files,
  web pages, reviews, calendar events written by others, channel names). Writes that echo the
  object they change (delete_file, add_calendar_event_participants) are untrusted too.
* output_sensitivity follows the KAIROS suite taints (kairos/config/<suite>.yaml).
"""
from __future__ import annotations

from dataclasses import dataclass, field

R = ("read", True, False, "none")  # prefix of a plain read


def _read(trust: str, sens: str) -> tuple:
    return (*R, trust, sens)


def _write(reversible: bool, external: bool, impact: str, trust: str = "none",
           sens: str = "public") -> tuple:
    """A write; `trust`/`sens` describe its output when it echoes stored content."""
    return ("write", reversible, external, impact, trust, sens)


@dataclass(frozen=True)
class SubAgent:
    id: str
    name: str
    scope: str  # MultiAgentDojo "Agent Scope" column
    tools: list[str] = field(default_factory=list)


ORCHESTRATOR = SubAgent(
    id="orchestrator",
    name="Orchestrator",
    scope="Talks to the user, splits the request into sub-tasks, delegates them to the "
    "specialised agents and returns the final answer. Has no tools of its own.",
)

SUITES: dict[str, list[SubAgent]] = {
    "workspace": [
        SubAgent("email", "Email Agent", "Read, search, send, and delete emails.",
                 ["send_email", "delete_email", "get_unread_emails", "get_sent_emails",
                  "get_received_emails", "get_draft_emails", "search_emails",
                  "search_contacts_by_name", "search_contacts_by_email"]),
        SubAgent("calendar", "Calendar Agent",
                 "Read the date and events; create, cancel, and reschedule them.",
                 ["get_current_day", "search_calendar_events", "get_day_calendar_events",
                  "create_calendar_event", "cancel_calendar_event", "reschedule_calendar_event",
                  "add_calendar_event_participants"]),
        SubAgent("drive", "Drive Agent",
                 "List, search, read, create, share, and delete files from the drive.",
                 ["append_to_file", "search_files_by_filename", "create_file", "delete_file",
                  "get_file_by_id", "list_files", "share_file", "search_files"]),
    ],
    "banking": [
        SubAgent("transactions", "Transactions Agent",
                 "Read balance and history; send and schedule payments.",
                 ["get_iban", "send_money", "schedule_transaction", "update_scheduled_transaction",
                  "get_balance", "get_most_recent_transactions", "get_scheduled_transactions"]),
        SubAgent("files", "Files Agent", "Read files on disk.", ["read_file"]),
        SubAgent("account", "Account Agent",
                 "Read the profile; update the account password or personal details.",
                 ["get_user_info", "update_password", "update_user_info"]),
    ],
    "slack": [
        SubAgent("slack", "Slack Agent", "Read and send messages; manage channels and members.",
                 ["get_channels", "add_user_to_channel", "read_channel_messages", "read_inbox",
                  "send_direct_message", "send_channel_message", "get_users_in_channel",
                  "invite_user_to_slack", "remove_user_from_slack"]),
        SubAgent("web", "Web Agent", "Read and post web pages.", ["get_webpage", "post_webpage"]),
    ],
    "travel": [
        SubAgent("hotels", "Hotels Agent", "Search hotels and make reservations.",
                 ["get_all_hotels_in_city", "get_hotels_prices", "get_rating_reviews_for_hotels",
                  "get_hotels_address", "reserve_hotel"]),
        SubAgent("restaurants", "Restaurants Agent", "Search restaurants and make reservations.",
                 ["get_all_restaurants_in_city", "get_cuisine_type_for_restaurants",
                  "get_restaurants_address", "get_rating_reviews_for_restaurants",
                  "get_dietary_restrictions_for_all_restaurants",
                  "get_contact_information_for_restaurants", "get_price_for_restaurants",
                  "check_restaurant_opening_hours", "reserve_restaurant"]),
        SubAgent("car_rental", "Car Rental Agent", "Search rental cars and make reservations.",
                 ["get_all_car_rental_companies_in_city", "get_car_types_available",
                  "get_rating_reviews_for_car_rental", "get_car_fuel_options",
                  "get_car_rental_address", "get_car_price_per_day", "reserve_car_rental"]),
        SubAgent("assistant", "Assistant Agent",
                 "Read and identify flights; manage calendar and email.",
                 ["get_user_information", "get_flight_information", "create_calendar_event",
                  "search_calendar_events", "get_day_calendar_events", "cancel_calendar_event",
                  "send_email"]),
    ],
}

# MultiAgentDojo Table I tool counts, checked by the generator and the tests.
TABLE_COUNTS = {
    "workspace": {"email": 9, "calendar": 7, "drive": 8},
    "banking": {"transactions": 7, "files": 1, "account": 3},
    "slack": {"slack": 9, "web": 2},
    "travel": {"hotels": 5, "restaurants": 9, "car_rental": 7, "assistant": 7},
}

ANNOTATIONS: dict[str, dict[str, tuple]] = {
    "banking": {
        "get_iban": _read("trusted", "high"),
        "get_balance": _read("trusted", "high"),
        "get_most_recent_transactions": _read("untrusted", "high"),  # incoming subjects
        "get_scheduled_transactions": _read("trusted", "high"),
        "read_file": _read("untrusted", "low"),  # bills and notices from third parties
        "get_user_info": _read("trusted", "high"),
        "send_money": _write(False, True, "high"),
        "schedule_transaction": _write(False, True, "high"),
        "update_scheduled_transaction": _write(False, True, "high"),
        "update_password": _write(False, False, "high"),
        "update_user_info": _write(False, False, "high"),
    },
    "slack": {
        "get_channels": _read("untrusted", "low"),  # channel names are user-chosen
        "get_users_in_channel": _read("trusted", "low"),
        "read_channel_messages": _read("untrusted", "high"),
        "read_inbox": _read("untrusted", "high"),
        # a GET to an arbitrary URL reaches that server: read, but external
        "get_webpage": ("read", True, True, "low", "untrusted", "public"),
        "send_direct_message": _write(False, True, "high"),
        "send_channel_message": _write(False, True, "high"),
        "post_webpage": _write(False, True, "high"),
        "add_user_to_channel": _write(False, True, "high"),
        "invite_user_to_slack": _write(False, True, "high"),
        "remove_user_from_slack": _write(False, True, "high"),
    },
    "travel": {
        "get_user_information": _read("trusted", "high"),
        "get_flight_information": _read("trusted", "public"),
        "get_all_hotels_in_city": _read("trusted", "public"),
        "get_hotels_prices": _read("trusted", "public"),
        "get_hotels_address": _read("trusted", "public"),
        "get_rating_reviews_for_hotels": _read("untrusted", "public"),
        "get_all_restaurants_in_city": _read("trusted", "public"),
        "get_cuisine_type_for_restaurants": _read("trusted", "public"),
        "get_restaurants_address": _read("trusted", "public"),
        "get_rating_reviews_for_restaurants": _read("untrusted", "public"),
        "get_dietary_restrictions_for_all_restaurants": _read("trusted", "public"),
        "get_contact_information_for_restaurants": _read("trusted", "public"),
        "get_price_for_restaurants": _read("trusted", "public"),
        "check_restaurant_opening_hours": _read("trusted", "public"),
        "get_all_car_rental_companies_in_city": _read("trusted", "public"),
        "get_car_types_available": _read("trusted", "public"),
        "get_rating_reviews_for_car_rental": _read("untrusted", "public"),
        "get_car_fuel_options": _read("trusted", "public"),
        "get_car_rental_address": _read("trusted", "public"),
        "get_car_price_per_day": _read("trusted", "public"),
        "search_calendar_events": _read("untrusted", "high"),
        "get_day_calendar_events": _read("untrusted", "high"),
        "reserve_hotel": _write(False, True, "low"),
        "reserve_restaurant": _write(False, True, "low"),
        "reserve_car_rental": _write(False, True, "low"),
        "create_calendar_event": _write(True, True, "low"),
        "cancel_calendar_event": _write(False, True, "low"),
        "send_email": _write(False, True, "high"),
    },
    "workspace": {
        "get_unread_emails": _read("untrusted", "high"),
        "get_received_emails": _read("untrusted", "high"),
        "search_emails": _read("untrusted", "high"),
        "get_sent_emails": _read("trusted", "high"),
        "get_draft_emails": _read("trusted", "high"),
        "search_contacts_by_name": _read("trusted", "low"),
        "search_contacts_by_email": _read("trusted", "low"),
        "get_current_day": _read("trusted", "public"),
        "search_calendar_events": _read("untrusted", "high"),
        "get_day_calendar_events": _read("untrusted", "high"),
        "list_files": _read("untrusted", "high"),
        "search_files": _read("untrusted", "high"),
        "search_files_by_filename": _read("untrusted", "high"),
        "get_file_by_id": _read("untrusted", "high"),
        "send_email": _write(False, True, "high"),
        "share_file": _write(False, True, "high"),
        "delete_email": _write(False, False, "low", "untrusted", "high"),  # echoes the email
        "delete_file": _write(False, False, "low", "untrusted", "high"),  # echoes the file
        "append_to_file": _write(True, False, "low"),
        "create_file": _write(True, False, "low"),
        "create_calendar_event": _write(True, True, "low"),
        "reschedule_calendar_event": _write(True, True, "low"),
        "cancel_calendar_event": _write(False, True, "low"),
        "add_calendar_event_participants": _write(False, True, "low", "untrusted", "high"),  # echoes the event
    },
}

ANNOTATION_FIELDS = ("effect", "reversible", "external", "impact", "output_trust", "output_sensitivity")
