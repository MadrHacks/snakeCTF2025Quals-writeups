# Free Start 2 [_snakeCtf 2025 Quals_]

**Category**: Crypto

**Author**: campa1102


## Description

It looks like it is impossible! We have used Anemoi in Sponge mode to generate the hash.

However, this hash was generated in such a way that an easy root can be found from the Anemoi polynomial representation. Just to be clear, there is no particular structure in the message. You must exploit the primitive representation.

Try to find the original message that is composed of 4 elements in the field.

**FLAG FORMAT** 
Once you have found the 4 items message `[m1, m2, m3, m4]`, the flag is `snakeCTF{M}` where `M` is the concatenation of `m1, m2, m3, m4`.

For example, if we obtain `[124, 43, 65, 13]`, the flag is `snakeCTF{124436513}`.

## Solution

Let's consider what we have:
- the `Anemoi` primitive ([Link to the paper](https://eprint.iacr.org/2022/840.pdf)) applied for 21 rounds.
- a target hash value `H`.
- a fixed input part (the initial capacity). Let's call it `C`.

The objective is to find a pre-image of the given hash function used in Sponge Mode.

The polynomial modelling we are referring to is given in this [paper](https://eprint.iacr.org/2025/814). Of this work, the only part you need to read is how to construct the polynomial modelling for `Anemoi` and how to compute its GB. 
Computing the GB for `Anemoi` is very easy, even for many rounds. Moreover, for $\alpha = 3$ (the degree of function `E` in the non-linear layer), we can use either the `degrevlex` or the `wdegrevlex` monomial orderings. The latter one requires a list of weights whose values can be computed as in Section 6 of the above-mentioned paper. In this case we will use the `wdegrevlex` monomial ordering.

Then:
1) construct the polynomial modelling for `Anemoi` (define the variables, the weights and the equations)
2) compute the GB by using `SageMath` (you don't need Magma).

Once the GB has been computed (extremely fast, no worries), the paper presents the computation of some univariate polynomial etc. However, those methodologies are impossible to apply for 21 rounds (neither in your entire life). 


The description suggests that the message has no particular structure, but it was chosen in such a way that an easy root is easy to find. 
`Anemoi` non-linear layer involves degree 2 equations: $Q_\gamma$ and $Q_\delta$. Both the functions are using $g = 3$.

Finding roots can be done in multiple way and one of them is computing the resultant between two polynomials to eliminate one common variable and to factorize the resulting polynomial. The roots of that polynomial are also roots of the original polynomials (under certain conditions). 


Let R denote the number of rounds, the GB of `Anemoi` is composed of 4 types of equations:
1) 1 equations whose leading monomial is $y_0$
2) R equations whose leading monomials are $y_i^2$ for $1 \le i \le R$
3) R equations whose leading monomials are $s_i^{(\alpha+1)}$ for $1 \le i \le R$
4) R equations whose leading monomials are $y_is_i$ for $1 \le i \le R$.

If we consider the last equation of set (3) (say `f`) and the last equation of set (4) (say `g`), if we compute 

$$
r = \mathrm{Res}_{y_{R-1}}(f,g)
$$ 

and we factorize $r$ (which will be a bivariate equation), we obtain an immediate solution for $s_R$. Due to the degree 2 equations in the Anemoi non-linear layer, this value is always the same and it depends on `g`. 

Once we have that value, it is just a matter of back-substitutions (also considering the equations of set (2)) to compute the remaining values. In this way we can use either the Anemoi inverse permutation or the resolution of the other polynomials to get the two inputs.


### Application to the entire sponge
The previous method considers 1 application of Anemoi. In the given Sponge, we apply Anemoi 4 times, and to get the inputs we start from the last application. 
When part of the input is not fixed, this methodology must be slightly modified. Indeed, we must consider the polynomial modelling of R+1 rounds and fix one of the inputs to a random value. Moreover, the first round must use a random constant, and we use the constants for the R rounds instance starting from the second round. 

Then, we proceed in the same way, but our target input values become the inputs to the second round. In this way we obtain the correct input for a R-rounds instance and not for the R+1 rounds instance. 

This method must be applied for the last 3 message blocks.

For the first message block, we apply everything to R rounds. In this case, the second input is fixed with the given initial capacity and the easy root permits to obtain the first input, which will also be the first message block. 

Denote as $\mathtt{Anemoi}_R$ the application of Anemoi for R rounds. 
Obtaining a two blocks message that goes to the same `H` and start with a capacity `C` can be done as follows:
- Apply the technique to $\mathtt{Anemoi}_{R+1}(?, 0) \circeq (H,?)$. Build the GB for R+1 rounds. Compute the resultant, find the root and go back to obtain the inputs to round 2 (say $(t_{1,2}, t_{2,2})$). In this way, we know that $\mathtt{Anemoi}(t_{1,2}, t_{2,2}) = (H,a_2)$. In addition, we also obtain the value of $a_2$.
 - Apply the technique to $\mathtt{Anemoi}_{R}(?, C) \circeq (?,t_{2,2})$. Build the GB for R rounds. Compute the resultant, find the root and go back to obtain the inputs to round 1 (say $(t_{1,1}, t_{2,1})$). In this way, we know that $\mathtt{Anemoi}(t_{1,1}, t_{2,1}) = (a_1,t_{2,2})$. In addition, we also obtain the value of $a_1$. 
- $t_{2,1}$ must be equal to $C$
- $m_1 = t_{1,1}$
- $m_2 = t_{1,2} - a_1$


# Considerations

I agree that the challenge would have been better with only 1 application of Anemoi.