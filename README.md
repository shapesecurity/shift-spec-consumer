# Shift Spec Consumer

## About

This module parses the [Shift specification](https://github.com/shapesecurity/shift-spec) into a more usable form.


## Installation

```sh
npm install shift-spec-consumer
```


## Usage

```es6
let specConsumer = require("shift-spec-consumer").default;
let {nodes, enums, namedTypes} = specConsumer(/* contents of spec.idl */, /* contents of attribute-order.conf */);
```

The object returned by calling this module's default export appropriately has three keys: `node`, `nums`, and `namedTypes`. All are ES2015 `Map`s.

`nodes` is a map from node names (as strings) to objects of the form
```js
{attributes, isLeaf, parents}
```

where
- `attributes` is an ordered list of objects of the form `{name, type, inherited}`, where those attributes are respectively a string, a type (see below), and a boolean indicating whether this field is inherited.
- `isLeaf` is a boolean indicating whether this node has no descendents
- `parents` is a list of names of nodes from which this node descends.

`enums` is a map from names to lists of strings, which were enums in the spec.

`namedTypes` is a map from type names to types (see below).

A `type` is a two-key object `{kind, argument}`, where
- `kind` is one of `'nullable', 'union', 'list', 'value', 'node', 'enum', 'namedType'`
- `argument` depends on `kind`. For
  - `nullable` it is a type
  - `union` it is a list of types
  - `list` it is a type
  - `value` it is one of `'string', 'boolean', 'double'`
  - `node` it is a key in `nodes`
  - `enum` it is a key in `nums`
  - `namedType` it is a key in `namedTypes`.


## Contributing

* Open a Github issue with a description of your desired change. If one exists already, leave a message stating that you are working on it with the date you expect it to be complete.
* Fork this repo, and clone the forked repo.
* Create a feature branch. Make your changes.
* Make a commit that includes the text "fixes #*XX*" where *XX* is the Github issue.
* Open a Pull Request on Github.


## License

    Copyright 2016 Shape Security, Inc.

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
