/**
 * Copyright 2016 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

"use strict";

let webIDL = require('webidl2');

let nodes;
let enums;
let idlTypes;
let superTypes;
let namedTypesIDL;
let namedTypes;
let valueTypes;

let spec;
let attrOrders;


function parseAttrOrder(f) {
  let attrOrder = new Map;
  let current = null;
  for (let line of f.split('\n')) {
    line = line.trim();
    if (line === '') continue;
    if (line[0] === '[') {
      let matches = line.match(/^\[([^\]]*)\]$/);
      if (!matches) {
        throw `Couldn't parse ${line}`;
      }
      let type = matches[1]
      current = [];
      attrOrder.set(type, current);
    } else {
      current.push(line);
    }
  }
  return attrOrder;
}

function unsortedArrayEquals(a, b) {
  if (a.length !== b.length) return false;
  let x = a.slice(0).sort();
  let y = b.slice(0).sort();
  return x.every((v, i) => y[i] === v);
}

function Nullable(t) {
  return {kind: 'nullable', argument: t};
}

function Union(t) {
  return {kind: 'union', argument: t};
}

function List(t) {
  return {kind: 'list', argument: t};
}

function Value(t) {
  return {kind: 'value', argument: t};
}

function Node(t) {
  return {kind: 'node', argument: t};
}

function NamedType(t) {
  return {kind: 'namedType', argument: t};
}

function Enum(t) {
  return {kind: 'enum', argument: t};
}

function isSimpleIdlType(type) {
  return !type.sequence && !type.generic && !type.nullable && !type.array && !type.union && typeof type.idlType === 'string';
}


function inherits(type, parent) {
  nodes.get(type).parents.push(parent);
  superTypes.add(parent);
}

function idlTypeToType(t) {
  // converts a type as returned by the parser to a type as defined above
  if (typeof t === 'string') {
    if (nodes.has(t)) {
      return Node(t);
    }
    if (valueTypes.has(t)) {
      return valueTypes.get(t);
    }
    if (namedTypes.has(t)) {
      return NamedType(t);
    }
    if (enums.has(t)) {
      return Enum(t);
    }
    throw `Unidentified type ${t}`;
  }

  if (isSimpleIdlType(t)) {
    return idlTypeToType(t.idlType);
  }

  if (t.nullable) {
    if (t.union) {
      if (t.sequence || t.generic || t.array || !Array.isArray(t.idlType)) {
        throw `Complex nullable-union type ${JSON.stringify(t, null, '  ')}`;
      }
      return Nullable(Union(t.idlType.map(idlTypeToType)));
    }
    if (t.sequence || t.generic || t.array || t.union || typeof t.idlType !== 'string') {
      throw `Complex nullable type ${JSON.stringify(t, null, '  ')}`;
    }
    return Nullable(idlTypeToType(t.idlType));
  }

  if (t.array === 1) {
    if (t.union) {
      if (t.sequence || t.generic || !Array.isArray(t.idlType)) {
        throw `Complex array-of-union type ${JSON.stringify(t, null, '  ')}`;
      }
      if (t.nullableArray[0]) {
        return List(Nullable(Union(t.idlType.map(idlTypeToType))));
      }
      return List(Union(t.idlType.map(idlTypeToType)));
    }
    if (t.sequence || t.generic || typeof t.idlType !== 'string') {
      throw `Complex array type ${JSON.stringify(t, null, '  ')}`;
    }
    if (t.nullableArray[0]) {
      return List(Nullable(idlTypeToType(t.idlType)));
    }
    return List(idlTypeToType(t.idlType));
  }

  if (t.union) {
    if (t.sequence || t.generic || t.array || !Array.isArray(t.idlType)) {
      throw `Complex union type ${JSON.stringify(t, null, '  ')}`;
    }
    return Union(t.idlType.map(idlTypeToType));
  }

  throw `Unsupported IDL type ${JSON.stringify(t, null, '  ')}`;
}

function setAttrs(name) {
  let type = nodes.get(name);
  if (type.attributes) return;
  let attrs = type.attributes = [];

  type.parents.forEach(p => {
    setAttrs(p);
    attrs.push(...nodes.get(p).attributes.map(a => ({
      name: a.name,
      type: a.type,
      inherited: true
    })));
  });

  attrs.push(...idlTypes.get(name).members.filter(t => t.name !== 'type').map(t => ({
    name: t.name,
    type: idlTypeToType(t.idlType),
    inherited: false
  })));
  let attrOrder = attrOrders.get(name);
  if (attrOrder === void 0) {
    throw `${name} does not have an attribute ordering specified`;
  }
  if (!unsortedArrayEquals(attrOrder, attrs.map(a => a.name))) {
    throw `${name}'s ordered attribute list (${JSON.stringify(attrOrder)}) does not agree with the list of attributes derived from the IDL (${JSON.stringify(attrs.map(a => a.name))})`;
  }

  attrs.sort((a, b) => attrOrder.indexOf(a.name) - attrOrder.indexOf(b.name));
}


exports.default = function(shiftSpecIdl, shiftSpecAttributeOrdering) {

  nodes = new Map;
  enums = new Map;
  idlTypes = new Map;
  superTypes = new Set;
  namedTypesIDL = new Map;
  namedTypes = new Map;
  valueTypes = new Map([['DOMString', Value('string')], ['boolean', Value('boolean')], ['double', Value('double')]]);

  spec = webIDL.parse(shiftSpecIdl);
  attrOrders = parseAttrOrder(shiftSpecAttributeOrdering);

  // First set up the types
  for (let type of spec) {
    if (type.type === 'interface') {
      idlTypes.set(type.name, type);
      if (nodes.has(type.name) || namedTypesIDL.has(type.name) || enums.has(type.name)) {
        throw `Overloaded type ${type.name}`;
      }
      nodes.set(type.name, {
        isLeaf: true,
        parents: []
      });
      if (type.inheritance !== null) {
        inherits(type.name, type.inheritance);
      }
    } else if (type.type === 'implements') {
      inherits(type.target, type.implements);
    } else if (type.type === 'typedef') {
      if (nodes.has(type.name) || namedTypesIDL.has(type.name) || enums.has(type.name)) {
        throw `Overloaded type ${type.name}`;
      }
      namedTypesIDL.set(type.name, type.idlType);
    } else if (type.type === 'enum') {
      if (nodes.has(type.name) || namedTypesIDL.has(type.name) || enums.has(type.name)) {
        throw `Overloaded type ${type.name}`;
      }
      enums.set(type.name, type.values);
    } else {
      throw `Unsupported type ${type}`;
    }
  }

  superTypes.forEach(t => {nodes.get(t).isLeaf = false;});
  namedTypesIDL.forEach((v, k) => namedTypes.set(k, idlTypeToType(v)));

  // Then set up the attributes for each type
  for (let name of nodes.keys()) {
    setAttrs(name);
  }

  return {nodes, enums, namedTypes};
}
