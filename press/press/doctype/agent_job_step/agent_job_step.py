# -*- coding: utf-8 -*-
# Copyright (c) 2020, Frappe and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class AgentJobStep(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		agent_job: DF.Link
		data: DF.Code | None
		duration: DF.Time | None
		end: DF.Datetime | None
		output: DF.Code | None
		start: DF.Datetime | None
		status: DF.Literal[
			"Pending", "Running", "Success", "Failure", "Skipped", "Delivery Failure"
		]
		step_name: DF.Data
		traceback: DF.Code | None
	# end: auto-generated types


# def on_doctype_update():
# 	# We don't need modified index, it's harmful on constantly updating tables
# 	frappe.db.sql_ddl("drop index if exists modified on `tabAgent Job Step`")
# 	frappe.db.add_index("Agent Job Step", ["creation"])

def on_doctype_update():
    doctype = "Agent Job Step"

    # Drop any index on the `modified` column safely
    try:
        db_type = getattr(frappe.db, "db_type", "") or frappe.conf.get("db_type")
    except Exception:
        db_type = None

    if db_type == "postgres":
        # Find all indexes on this table that reference the `modified` column
        rows = frappe.db.sql(
            """
            SELECT indexname
            FROM pg_indexes
            WHERE tablename = %s
              AND indexdef ILIKE %s
            """,
            (doctype, "%modified%")
        )
        for r in rows or []:
            index_name = r[0]
            frappe.db.sql_ddl(f'DROP INDEX IF EXISTS "{index_name}";')
    else:
        # MySQL / MariaDB: original syntax works
        frappe.db.sql_ddl('DROP INDEX IF EXISTS modified ON `tabAgent Job Step`;')

    # Re-add creation index
    frappe.db.add_index(doctype, ["creation"])
