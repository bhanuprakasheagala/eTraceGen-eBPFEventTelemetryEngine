# Commenting Guidelines

This project uses a selective Doxygen-first strategy to balance clarity and maintenance cost.

## 1. Use Full Doxygen For
- public interfaces in headers
- ABI-critical structures and contracts
- non-trivial kernel eBPF helpers/handlers
- code paths with important failure behavior

Recommended tags:
- `@brief`
- `@param`
- `@return`
- optional `@note` when behavior constraints matter

## 2. Keep Brief Comments For
- trivial internal helpers
- obvious control-flow statements
- syntactic details that code already expresses clearly

## 3. Rules
- describe intent and operational relevance, not syntax
- keep comments truthful; update comments with behavior changes in same patch
- avoid duplicating information across many places
- when uncertain, prefer fewer but precise comments

## 4. Migration Strategy
- migrate one module at a time
- after each module migration: build, evaluate readability, then proceed


## 5. Terminology
- prefer `raw event payload` over `record` for byte-level collector input
- prefer `typed event payload` after decode/variant conversion
- use `event` for end-to-end lifecycle references
