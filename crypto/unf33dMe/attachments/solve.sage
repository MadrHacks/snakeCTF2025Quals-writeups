#!/usr/bin/env sage

import sys
from copy import deepcopy
from os import path

from Crypto.Hash import SHAKE256
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import long_to_bytes, bytes_to_long


class BabylonPoly:
    def __init__(self):
        self.setParams()
        self.genConstants()
        self.variables = [var(f"s{i}") for i in range(self.state_size)]
        self.R = PolynomialRing(self.F, self.variables)
        self.R.inject_variables(verbose=False)
        self.variables = [self.R(vs) for vs in self.variables]

    def setParams(self):
        self.exp = 3
        self.p = 65537
        self.nbytes = self.p.bit_length() // 8
        self.F = GF(self.p)
        self.state_size = 24
        self.rounds = 4

    def genConstants(self):
        shake = SHAKE256.new()
        shake.update(b"SNAKECTF")
        self.constants = []
        for _ in range(self.rounds):
            self.constants.append(self.F(int.from_bytes(shake.read(self.nbytes), 'big')))

    def compose(self, chunks):
        padded_message = b''
        for c in chunks:
            padded_message += long_to_bytes(c)
        message = unpad(padded_message, self.state_size * self.nbytes)
        return message

    def decompose(self, message):
        state = []
        padded_message = pad(message, self.state_size * self.nbytes)
        for i in range(0, len(padded_message), self.nbytes):
            chunk = bytes_to_long(padded_message[i:i + self.nbytes])
            state.append(chunk)
        return state

    def shuffle(self, state):
        for i in range(0, self.state_size, 2):
            t = state[i]
            state[i] = state[i + 1]
            state[i + 1] = t
        return state

    def add(self, state, constant):
        return [state[i] + constant for i in range(self.state_size)]

    def xor(self, a, b):
        return [a[i] + b[i] for i in range(self.state_size)]

    def sbox(self, state):
        return [(state[i]) ^ self.exp for i in range(self.state_size)]

    def round(self, state, r):
        state = self.sbox(state)
        state = self.add(state, self.constants[r])
        return state

    def permute(self, state, key):
        state = self.xor(state, key)
        for r in range(self.rounds):
            state = self.round(state, r)
        return state

    def hash(self, digest, IV):
        output = self.permute(self.variables, IV)
        digest2 = self.xor(output, self.shuffle(self.variables))
        equation = [digest2[i] - digest[i] for i in range(self.state_size)]
        return equation


if __name__ == "__main__":
    babylon = BabylonPoly()

    out_dir = sys.argv[1]
    with open(path.join(out_dir, "out.txt"), "r") as f:
        digest = eval(f.readline())
        IV = eval(f.readline())

    for i in range(babylon.state_size):
        digest[i] = babylon.F(digest[i])
        IV[i] = babylon.F(IV[i])

    eqs = babylon.hash(digest, IV)

    sols = [[]]
    for i in range(0, babylon.state_size, 2):
        eq2 = eqs[i].resultant(eqs[i + 1], eqs[i + 1].variables()[0])
        fs2 = factor(eq2)
        curr_sol = []
        for f2 in fs2:
            if f2[0].degree() == 1:
                var2 = f2[0].variables()[0]
                sol2 = (-1 * eval(str(f2[0]).replace(str(var2), '(0)').replace('^', '**'))) % babylon.p
                eq1 = eval(str(eqs[i]).replace(str(var2), f'({sol2})').replace('^', '**'))
                fs1 = factor(eq1)
                for f1 in fs1:
                    if f1[0].degree() == 1:
                        var1 = f1[0].variables()[0]
                        sol1 = (-1 * eval(str(f1[0]).replace(str(var1), '(0)').replace('^', '**'))) % babylon.p
                        curr_sol.append([sol1, sol2])
        new_sols = []
        for j in range(len(sols)):
            for jj in range(len(curr_sol)):
                new_sols.append(sols[j] + curr_sol[jj])
        sols = deepcopy(new_sols)

    for s in sols:
        try:
            flag = babylon.compose(s)
            if b"snakeCTF{" in flag:
                print(flag.decode())
        except:
            continue
