# axa/authz

Go module `github.com/ArmornetIO/axa/authz`. Apache 2.0.

- `authz`: a checker that asks OpenFGA whether a subject holds a relation on an
  object, turning sign-in groups into contextual tuples on the way.
- `authz/model`: declares an OpenFGA model in Go and returns the validated model
  plus typed helpers that build tuples and check requests. *In progress.*
- `authz/rbac`, `abac`, `cbac`, `mac`, `authztest`: role, attribute, context and
  mandatory access control on top of `model`, and an in-process OpenFGA for
  tests. *Planned:* each holds only its contract examples, behind the
  `contract` build tag until it is built.

It depends on OpenFGA and its protobuf types only, and imports nothing else from
identity. Nothing here makes a network call except the checker's OpenFGA client.
