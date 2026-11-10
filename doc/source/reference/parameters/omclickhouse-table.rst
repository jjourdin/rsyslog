.. SPDX-License-Identifier: Apache-2.0

.. _param-omclickhouse-table:
.. _omclickhouse.parameter.input.table:

table
=====

.. index::
   single: omclickhouse; table
   single: table

.. summary-start

ClickHouse table used by format jsoneachrow. Required in that mode.

.. summary-end

This parameter applies to :doc:`/configuration/modules/omclickhouse`.

:Name: table
:Scope: input
:Type: string
:Default: none
:Required?: yes, when format is jsoneachrow
:Introduced: not specified

Description
-----------
Used only with ``format="jsoneachrow"``. The value is placed in
``INSERT INTO <table> FORMAT JSONEachRow``. It must be a table name or
``database.table``. Each side contains only ASCII letters, digits, and
underscore. One dot is allowed between the database and the table. The
maximum length is 128 characters. Anything else is rejected so the value
cannot change the query string.

Setting ``table`` together with ``format="values"`` is a configuration
error. In that mode the INSERT statement comes from the template.

Input usage
-----------
.. _omclickhouse.parameter.input.table-usage:

.. code-block:: rsyslog

   module(load="omclickhouse")
   template(name="ClickHouseJson" type="string"
            string="{\"message\":\"%msg:::json%\"}")
   action(type="omclickhouse" format="jsoneachrow" table="soc.events"
          template="ClickHouseJson")

See also
--------
See also :doc:`/configuration/modules/omclickhouse`.
