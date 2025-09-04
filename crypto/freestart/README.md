# Free Start [_snakeCtf 2025 Quals_]

**Category**: Crypto

**Author**: campa1102

## Description

It looks like it is impossible!

## Solution

The intended solution was the one for `Free Start 2`. However, we figured out that `Free Start` was solvable in two naive ways. 
As a consequence, the flag for Free Start could have helped for solving Free Start 2, as many of the participants have noticed.

Here we provide two solutions for Free Start. 

### Solution 1
Consider the file `challenge.py`.

After the user has sent its message, the service checks the following conditions:

```py
if len(input_message) < 2:
    print("Your message must have at least two blocks")
    break
if not all([v < PRIME for v in input_message]):
    print("Your message must be composed of values in the field!")
    break
if "|".join(map(str, input_message)) in "|".join(map(str, message)):
    print("Your message cannot contain subsequences of my message!")
    break
```

Let's consider the original message provided by the service. It is composed of 5 elements in $\mathbb{F}_p$. 
Although we checked that the user input does not contain subsequences of the original message provided by the service, the service itself was not checking if the user message was containing negative elements. 

As a consequence, let $$M = m_1 || m_2 || m_3 || m_4 || m_5$$ be the message provided by the service. 

The message $$\tilde{M} = m_1 - p || m_2 - p || m_3 - p || m_4- p ||m_5 - p$$ will pass all the checks. 
Indeed $m - p \equiv m \mod{p}$.

### Solution 2
Let's consider what we have:
- the `Anemoi` primitive ([Link to the paper](https://eprint.iacr.org/2022/840.pdf))
- a target hash value `H`.

We must provide a message and an initial capacity value such that the computed hash value coincides with the target hash provided by the service.


- `Anemoi` is an invertible operation. Hence, it is straightforward to build its inverse, let's denote it as $\mathtt{Anemoi}^{-1}$. 
- We have the target hash, which is only 1 field elements. The other one can be randomly chosen by the user. Assume we set that value to 0. As a consequence, we suppose the output of the last Anemoi application to be `[H, 0]`. 

Computing a message is easy by just applying the inverse operation and randomly choosing the message blocks. For example, obtaining a two blocks message that goes to the same `H` can be done as follows:
- $(t_{1,2}, t_{2,2}) = \mathtt{Anemoi}^{-1}(H,0)$
- $m_2$ is chosen at random from $\mathbb{F}_p$
- $(\widetilde{t_{1,2}}, t_{2,2}) = (t_{1,2} - m_2, t_{2,2})$
- $(t_{1,1}, t_{2,1}) = \mathtt{Anemoi}^{-1}(\widetilde{t_{1,2}}, t_{2,2})$
- $m_1 = t_{1,1}$.
- The initial capacity is $t_{2,1}$.



### Flag (without the randomly generated part)
`snakeCTF{resultant_computation_can_help_a_lot_if_some_roots_are_easy_to_find}`
