..
    Portions created or assigned to Cisco Systems, Inc. are
    Copyright (c) 2010 Cisco Systems, Inc.  All Rights Reserved.
..

.. include:: entities
.. meta::
   :description: The philosophy behind |JWC|'s API design
   :copyright: Copyright (c) 2010 Cisco Systems, Inc.  All Rights Reserved.
   :dateModified: 2010-12-07

|JWC|: API Philosophy and Guidelines
====================================

.. contents:: Table of Contents

.. sectnum::

Overview
~~~~~~~~

|JWC| adheres to a consistent API philosophy.  The goal is to provide a set of
types and functions that follow the same basic patterns and conventions. This
helps users of the API to quickly understand and become proficient in |JWC|.

Most of |JWC| is designed around objects, and the functions that operate on
them.  Some utility functions are provided to transform data from one form to
another, or to validate inputs without completely processing.

|JWC| is "thread agnostic", providing a well-defined set of objects around
which the API user can determine how and when to protect. Memory management is
uniform, with consistent pattern for allocating and releasing data.

API Basics
~~~~~~~~~~

General Pattern
---------------

Most of the public functions in |JWC| return a bool to indicate
success/failure, and take an optional error context to provide details about
the failure.

For example::

    JABBERWERX_API bool jw_htable_put(jw_htable *tbl,
                                      const void *key,
                                      void *value,
                                      void **pvalue,
                                      jw_err *err)

If the call to this function succeeds, it returns ``true``.  Otherwise
``false`` is returned, and populates the structure pointed to by ``err`` to
describe the error.

If ``err`` is NULL, failed calls will simply return ``false``, and not attempt
to describe the error details.

Getters
-------

These are functions that return a value as-is, usually from within an object.
The value in question is returned directly instead, and is usually owned by the
object it was obtained from. An example is::
  
    JABBERWERX_API void *jw_jid_get_localpart(jw_jid *)
    
Setters
-------

These functions change, update, or remove data from an object. They follow the
general pattern, and the individual functions indicate whether the object now
owns the data, makes a copy of it, or expects the user to retain ownership and
release when done. An example is::

    JABBERWERX_API bool jw_dom_set_value(jw_dom *node,
                                         const char *value,
                                         jw_err *err);

Transformers
------------

These functions transform one type of data into another.  The source data may
be unstructured (e.g. string or binary array) or an object (e.g. jw_dom), while
the result is unstructured. The data and the length are returned in the last
two arguments before the jw_err pointer. An example is::

    JABBERWERX_API bool jw_serialize_xml(jw_dom *dom,
                                         char **xml,
                                         size_t *len,
                                         jw_err *err);

See the section on unstructured data below for details of the outbound
arguments.

Constructors
------------

These functions create an object type.  They may take any number of parameters,
as dictated by the type, but the last argument (before the error) is a pointer
to hold the created object, and follows the general function pattern. An
example is::

    JABBERWERX_API bool jw_htable_create(int buckets,
                                         jw_htable_hashfunc hash,
                                         jw_htable_cmpfunc cmp,
                                         jw_htable **tbl,
                                         jw_err *err);

Destructors
-----------
These are functions that release memory, performing operations that cannot
fail.  They only take the object to be destroyed, and do not generally return
any value.  An example is::
  
    JABBERWERX_API void jw_htable_destroy(jw_htable *tbl);

Invariants and Assertions
-------------------------

Most of the functions include invariants. These are conditions that must be
met for the function to begin executing.  All invariants are validated using
assert(), and are documented with a specific callout for each function.

Error Reporting
~~~~~~~~~~~~~~~

|JWC| follows an error reporting and handing policy that emphasizes ease of
use and performance. Functions rely on invariants and asserts to call out
programming errors, returns values directly when additional error information
is unavailable, and allows the API user to opt-in for additional error
information when a particular function is called.

The ``jw_err`` Structure
------------------------

The ``jw_err`` structure is managed by the API user; typically it is allocated
on the stack, and the address to the structure is passed in::

    jw_err  err;
    if (!jw_htable_put(tbl, "some key", "some value", NULL, &err))
    {
        // failed; examine structure for details...
    }

The specific member values within the ``jw_err`` structure are
constants.  API users do not need to be concerned with freeing their memory.

The structure contains the following members:

* ``jw_errcode code``: This is the numeric code for the failure.
* ``const char *message``: This is a pre-defined error message for ``code``.
* ``const char *function``: This is name of the specific function where the
  error occurred.
* ``const char *file``: This is the file where the error occurred.
* ``unsigned long line``: This is the line number in ``file`` where the error
  occurred.

The ``message``, while human-readable, is not localized.  It, along with the
other member values, are meant for the API user for diagnostics.

Extending ``jw_err``
----------------------------

It is possible to extend ``jw_err`` for API extensions. The recommended way to
do this is to create a new structure that includes ``jw_err`` as its
first member::

    typedef struct
    {
        jw_err  err;
        custom_errcode  code;
    } custom_err;

Functions can take a ``custom_err``, and will also have a placeholder on the
built-in error conditions.  The error code for the ``jw_err`` structure should
be set to ``JW_ERR_USER``, and any custom data provided must not require memory
management (e.g be literal values).

Data Types and Memory Management
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

|JWC| provides the routines necessary to release any memory allocated through
its APIs. There are two types of memory in |JWC|: object-based and unstructured.

Objects
-------

Object-based data is the most common form of data in |JWC|. This type of data
includes a type (whose structure is left hidden), with functions to create and
destroy it, as well as functions to access and manipulate its properties. The
user calls the create function to allocate and initialize the object, then
calls the destroy function to cleanup and release the object.

In general, the actual members of the object structures are left hidden by the
API.  The values are only accessed via getters and setters.  Usually, the data
for object members is owned by the object, and MUST NOT be released separately
from the object.

The API user MUST use the create function to allocate (and initialize)
object-based data, and MUST use the destroy function to release it. Unless
explicitly stated, any data associated with an object is owned by it. This data
MUST NOT be released separately; instead the object's destroy function will
release it.

Unstructured Data
-----------------

Unstructured data is usually either strings or binary arrays. This data is
often returned when transforming data; whether it be a binary array into a
base64-encoded string, generating a cryptographic hash, or turning a structured
DOM hierarchy into a string of UTF-8 encoded XML.

Unless explicitly stated in the API reference, the conventions of strings in
|JWC| are:

* Of type ``char *``
* UTF-8 encoded
* NULL terminated
* The length outbound argument in the API is optional, and MAY be NULL

The conventions of binary arrays in |JWC| are:

* Of type ``uint8_t *``
* The length is not encoded into the data; the API user SHOULD maintain this
  in a separate variable, which MUST be of type ``size_t``
* The length outbound argument in the API is required, and MUST NOT be NULL

Regardless of the type, |JWC| will allocate the memory on the user's behalf,
and provide both the data and its length via outbound arguments. Data allocated
by such functions MUST be released using the function ``jw_data_free()``.
Releasing memory using any other mechanism can lead to unexpected behavior.

Threading
~~~~~~~~~

Most of the APIs in |JWC| are not thread-safe.  For any given object instance,
the API user MUST ensure that only a single thread of execution is using it.
However, the APIs are generally self-contained; it is safe for the API user to
synchronize around a number of function calls against a given object instance.
