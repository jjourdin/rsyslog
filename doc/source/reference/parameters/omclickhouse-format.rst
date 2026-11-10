.. SPDX-License-Identifier: Apache-2.0

.. _param-omclickhouse-format:
.. _omclickhouse.parameter.input.format:

format
======

.. index::
   single: omclickhouse; format
   single: format

.. summary-start

Selects an INSERT ... VALUES body or newline-delimited JSONEachRow.

.. summary-end

This parameter applies to :doc:`/configuration/modules/omclickhouse`.

:Name: format
:Scope: input
:Type: word
:Default: values
:Required?: no
:Introduced: not specified

Description
-----------
``values`` posts the rendered template as the HTTP body. That body must
contain ``INSERT INTO``. In bulk mode the module still joins statements on
the ``VALUES`` clause. This is the historical behavior.

``jsoneachrow`` posts one JSON object per event, separated by newlines,
with ``Content-Type: application/x-ndjson``. The INSERT statement is the
``query`` URL parameter: ``INSERT INTO <table> FORMAT JSONEachRow``. A
template is required. The template must not enable SQL or JSON template
escaping. ``table`` is required.

Input usage
-----------
.. _omclickhouse.parameter.input.format-usage:

.. code-block:: rsyslog

   module(load="omclickhouse")
   template(name="ClickHouseJson" type="string"
            string="{\"message\":\"%msg:::json%\"}")
   action(type="omclickhouse" format="jsoneachrow" table="rsyslog.events"
          template="ClickHouseJson")

See also
--------
See also :doc:`/configuration/modules/omclickhouse`.
