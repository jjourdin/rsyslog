.. SPDX-License-Identifier: Apache-2.0

.. _param-omclickhouse-errorfile:
.. _omclickhouse.parameter.input.errorfile:

errorFile
=========

.. index::
   single: omclickhouse; errorFile
   single: errorFile
   single: omclickhouse; errorfile
   single: errorfile

.. summary-start

Records the URL, HTTP status, and ClickHouse reply for a failed insert.

.. summary-end

This parameter applies to :doc:`/configuration/modules/omclickhouse`.

:Name: errorFile
:Scope: input
:Type: word
:Default: none
:Required?: no
:Introduced: not specified

Description
-----------
If specified, each failed insert appends one JSON object. The object contains
the request URL, the HTTP status, and the ClickHouse reply. It does not
contain the event body. The file is created mode 0600.

The action suspends after the failure. The queue keeps the batch and retries
it. This file is a diagnostic. It is not a spool of events to replay.

.. note::
   A transport failure and a ClickHouse reject (HTTP status 400 or a reply
   that contains ``DB::Exception``, ``DB::NetException``, or
   ``DB::ParsingException``) both suspend the action. A single rejected row
   holds the batch until a later attempt succeeds or the queue discard
   policy drops it. There is no per-row skip.

Input usage
-----------
.. _omclickhouse.parameter.input.errorfile-usage:

.. code-block:: rsyslog

   module(load="omclickhouse")
   action(type="omclickhouse" errorFile="clickhouse-error.log")

See also
--------
See also :doc:`/configuration/modules/omclickhouse`.
