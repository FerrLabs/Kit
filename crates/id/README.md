# ferrlabs-id

Typed id newtypes over `Uuid`, so passing a user id where an organisation id belongs stops
compiling.

```rust
use ferrlabs_id::typed_id;

typed_id!(UserId);
typed_id!(OrgId);

let user = UserId::new_v7();
let org = OrgId::new_v7();

fn members_of(org: OrgId) -> Vec<UserId> { /* ... */ }

members_of(user); // does not compile
```

## Why

`Uuid` everywhere means every id is assignable to every parameter, and the compiler cannot tell a
tenant id from a row id. That is the shape an IDOR bug takes: a handler reads one id from the path
and passes it where another was meant, and nothing objects. A newtype per id turns that class of
mistake into a type error instead of a production incident.

Ids are UUID v7, so they are time-ordered and index well as a primary key. `new_ulid` is an alias
for `new_v7` for codebases that name them that way.

Each generated type derives `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `PartialOrd`,
`Ord`, `Serialize` and `Deserialize`, is `#[serde(transparent)]` so the wire format stays a plain
UUID string, and implements `Display`, `FromStr`, and conversion both ways with `Uuid`.

## Status

Part of [FerrLabs Kit](https://github.com/FerrLabs/Kit). MPL-2.0.
