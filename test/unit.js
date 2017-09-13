/**
 * Copyright 2016 Shape Security, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
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

import * as assert from "assert";
import specConsumer from "..";

suite('passing unit', () => {
  test('Trivial file passes', () => {
    const src = ``;
    const attributes = ``;
    let {enums, namedTypes, nodes} = specConsumer(src, attributes);
    assert.deepEqual({enums, namedTypes, nodes}, {enums: new Map, namedTypes: new Map, nodes: new Map});
    assert.equal(enums.size, 0);
    assert.equal(namedTypes.size, 0);
    assert.equal(nodes.size, 0);
  });

  test('Simple file passes', () => {
    const src = `interface A { attribute double x; };`;
    const attributes = `
      [A]
      x
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map,
      namedTypes: new Map,
      nodes: new Map([['A', {
        attributes: [{
          name: 'x',
          inherited: false,
          type: {
            kind: 'value',
            argument: 'double'
          }
        }],
        children: [],
        parents: []
      }]])
    });
  });

  test('"string" type is not an alias', () => {
    const src = `typedef DOMString string; interface A { attribute string x; };`;
    const attributes = `
      [A]
      x
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map,
      namedTypes: new Map,
      nodes: new Map([['A', {
        attributes: [{
          name: 'x',
          inherited: false,
          type: {
            kind: 'value',
            argument: 'string'
          }
        }],
        children: [],
        parents: []
      }]])
    });
  });

  test('Attribute order is enforced', () => {
    const src = `interface A { attribute double y; attribute double x; };`;
    const attributes = `
      [A]
      x
      y
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map,
      namedTypes: new Map,
      nodes: new Map([['A', {
        attributes: [{
          name: 'x',
          inherited: false,
          type: {
            kind: 'value',
            argument: 'double'
          }
        },
        {
          name: 'y',
          inherited: false,
          type: {
            kind: 'value',
            argument: 'double'
          }
        }],
        children: [],
        parents: []
      }]])
    });
  });

  test('Diamond inheritance is handled correctly', () => {
    const src = `
      interface A {
      };

      interface B : A {
        attribute double b;
      };

      interface C : A {
        attribute double c;
      };

      interface D : B {
        attribute double d;
      };
      D implements C;
      `;
    const attributes = `
      [A]

      [B]
      b

      [C]
      c

      [D]
      b
      c
      d
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map,
      namedTypes: new Map,
      nodes: new Map([
        ['A', {
          attributes: [],
          children: ['B', 'C'],
          parents: []
        }],
        ['B', {
          attributes: [{
            name: 'b',
            inherited: false,
            type: {
              kind: 'value',
              argument: 'double'
            }
          }],
          children: ['D'],
          parents: ['A']
        }],
        ['C', {
          attributes: [{
            name: 'c',
            inherited: false,
            type: {
              kind: 'value',
              argument: 'double'
            }
          }],
          children: ['D'],
          parents: ['A']
        }],
        ['D', {
          attributes: [{
            name: 'b',
            inherited: true,
            type: {
              kind: 'value',
              argument: 'double'
            }
          },
          {
            name: 'c',
            inherited: true,
            type: {
              kind: 'value',
              argument: 'double'
            }
          },
          {
            name: 'd',
            inherited: false,
            type: {
              kind: 'value',
              argument: 'double'
            }
          }],
          children: [],
          parents: ['B', 'C']
        }],
      ])
    });
  });

  test('Typedefs', () => {
    const src = `
      interface A {
        attribute B x;
      };

      typedef double B;
      `;
    const attributes = `
      [A]
      x
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map,
      namedTypes: new Map([['B', {kind: 'value', argument: 'double'}]]),
      nodes: new Map([['A', {
        attributes: [{
          name: 'x',
          inherited: false,
          type: {
            kind: 'namedType',
            argument: 'B'
          }
        }],
        children: [],
        parents: []
      }]])
    });
  });

  test('Enums', () => {
    const src = `
      interface A {
        attribute En x;
      };

      enum En { "1", "two" };
      `;
    const attributes = `
      [A]
      x
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map([['En', ['1', 'two']]]),
      namedTypes: new Map,
      nodes: new Map([['A', {
        attributes: [{
          name: 'x',
          inherited: false,
          type: {
            kind: 'enum',
            argument: 'En'
          }
        }],
        children: [],
        parents: []
      }]])
    });
  });

  test('Compound types parse', () => {
    const src = `
      interface A {
        attribute double a;
        attribute DOMString b;
        attribute B c;
        attribute double? d;
        attribute double[] e;
        attribute (B or C) f;
        attribute (B or C)?[] g;
      };

      interface B {};

      interface C {};
      `;
    const attributes = `
      [A]
      a
      b
      c
      d
      e
      f
      g

      [B]
      [C]
      `;

    assert.deepEqual(specConsumer(src, attributes), {
      enums: new Map,
      namedTypes: new Map,
      nodes: new Map([
        ['A', {
          attributes: [{
            name: 'a',
            inherited: false,
            type: {
              kind: 'value',
              argument: 'double'
            }
          },
          {
            name: 'b',
            inherited: false,
            type: {
              kind: 'value',
              argument: 'string'
            }
          },
          {
            name: 'c',
            inherited: false,
            type: {
              kind: 'node',
              argument: 'B'
            }
          },
          {
            name: 'd',
            inherited: false,
            type: {
              kind: 'nullable',
              argument: {
                kind: 'value',
                argument: 'double'
              }
            }
          },
          {
            name: 'e',
            inherited: false,
            type: {
              kind: 'list',
              argument: {
                kind: 'value',
                argument: 'double'
              }
            }
          },
          {
            name: 'f',
            inherited: false,
            type: {
              kind: 'union',
              argument: [
                {
                  kind: 'node',
                  argument: 'B'
                },
                {
                  kind: 'node',
                  argument: 'C'
                }
              ]
            }
          },
          {
            name: 'g',
            inherited: false,
            type: {
              kind: 'list',
              argument: {
                kind: 'nullable',
                argument: {
                  kind: 'union',
                  argument: [
                    {
                      kind: 'node',
                      argument: 'B'
                    },
                    {
                      kind: 'node',
                      argument: 'C'
                    }
                  ]
                }
              }
            }
          }],
          children: [],
          parents: []
        }],
        ['B', {
          attributes: [],
          children: [],
          parents: []
        }],
        ['C', {
          attributes: [],
          children: [],
          parents: []
        }],
      ])
    });
  });
});

suite('Failing unit', () => {
  test('Missing node in attribute list throws', () => {
    const src = `interface A {};`;
    const attributes = ``;
    
    assert.throws(() => specConsumer(src, attributes));
  });

  test('Additional node in attribute list throws', () => {
    const src = `interface A {};`;
    const attributes = `[A]\n[B]\n`;
    
    assert.throws(() => specConsumer(src, attributes));
  });

  test('Missing attribute throws', () => {
    const src = `interface A { attribute double x; };`;
    const attributes = `[A]`;

    assert.throws(() => specConsumer(src, attributes));
  });

  test('Additional attribute throws', () => {
    const src = `interface A { attribute double x; };`;
    const attributes = `[A]\nx\ny`;

    assert.throws(() => specConsumer(src, attributes));
  });

  test('Undefined type throws', () => {
    const src = `interface A { attribute B x; };`;
    const attributes = `[A]\nx`;

    assert.throws(() => specConsumer(src, attributes));
  });
});