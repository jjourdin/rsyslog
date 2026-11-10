.. SPDX-License-Identifier: Apache-2.0

.. _param-omclickhouse-asyncinsert:
.. _omclickhouse.parameter.input.asyncinsert:

asyncInsert
===========

.. index::
   single: omclickhouse; asyncInsert
   single: asyncInsert

.. summary-start

Adds ClickHouse async_insert and wait_for_async_insert to the request URL.

.. summary-end

This parameter applies to :doc:`/configuration/modules/omclickhouse`.

:Name: asyncInsert
:Scope: input
:Type: boolean
:Default: off
:Required?: no
:Introduced: not specified

Description
-----------
When enabled, the HTTP request URL gains
``async_insert=1&wait_for_async_insert=1``. ClickHouse accepts the batch
into its asynchronous insert buffer and the HTTP call waits until that
buffer is flushed. The default leaves the URL without those settings, so
existing configurations keep synchronous inserts.

The parameter applies to both ``format="values"`` and
``format="jsoneachrow"``.

Input usage
-----------
.. _omclickhouse.parameter.input.asyncinsert-usage:

.. code-block:: rsyslog

   module(load="omclickhouse")
   action(type="omclickhouse" asyncInsert="on")

See also
--------
See also :doc:`/configuration/modules/omclickhouse`.
