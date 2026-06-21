---
name: mass-assignment
description: Searches for Mass Assignment (Over-posting) vulnerabilities where ORMs or DB managers blindly bind all incoming JSON/Form properties directly into database models.
---

# Objective

Identify Mass Assignment vulnerabilities (CWE-915). This occurs when a framework
automatically binds user-supplied HTTP request parameters to internal object or
database model properties without an explicit allowlist. Attackers can inject
unexpected parameters (like `is_admin=true` or `wallet_balance=9999`) to
escalate privileges.

## Methodology

You are acting as an expert application security reviewer hunting for CWE-915.

## Typical patterns to check

1.  Use `grep_code` to look for ORM or object instantiation patterns:

- Node.js (Sequelize, TypeORM): `Model.create(req.body)`,
  `Model.update(req.body)`
- Python (Django, SQLAlchemy): `Model(**request.json)`,
  `User.update(request.form)`

1.  Trace the data being passed into the update/create function to see if it is
    a direct binding of user input (`req.body`, `request.json`, `req.query`).

## True-positive signals

- Passing the entire raw `req.body` object directly into an ORM's `create`,
  `update`, or `save` method without filtering.
- Updating an object by iterating over all keys in the user payload and applying
  them to the object dynamically (e.g.
  `for k, v in req.body.items(): setattr(obj, k, v)`).

## False-positive signals (do NOT flag)

- The application explicitly defines an allowlist of permitted fields (e.g.,
  destructuring
  `const { username, email } = req.body; User.create({ username, email })`).
- The framework/ORM natively protects against mass assignment via strict schema
  validations (e.g., Pydantic models with `extra="forbid"`, or Django Forms
  which natively filter fields).
- The update is performed on a safe, isolated model that contains no sensitive
  fields to begin with (e.g., a simple `Comment` model with only a `text`
  field).

## Output: severity guidance

- **Critical** if an attacker can overwrite privilege fields (e.g., `role`,
  `is_admin`, `tenant_id`).
- **High** if an attacker can bypass business logic (e.g., modifying `price`,
  `status`, `balance`).

## Output: CWE

- `CWE-915` (Improperly Controlled Modification of Dynamically-Determined Object
  Attributes)

## Output: rule_id slug

- `ai.mass-assignment-orm` (Direct raw binding to an ORM)
- `ai.mass-assignment-dynamic` (Dynamic attribute assignment via loop or
  unpacking)
