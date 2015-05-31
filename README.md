# StemFlow

StemFlow is an access-control engine library for StemJail.
It manage a set of domains who define their access control list.
A domain can transition to an other iff the destination is a superset of the source.

This engine can create an intersection domain according to a common access between multiple domains.
This is useful to get a minimal domain allowing a specific access.

This library is a work in progress.
The API may change.
