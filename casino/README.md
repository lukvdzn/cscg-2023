### ID: torukmagto

# Breaking DDH in multiplicative groups modulo a prime

## Decisional Diffie-Hellman (DDH)
The _DDH_ assumption states that given $g^a$, $g^b$, $g^c$ of 
a (multiplicative) cyclic group $G$ of order $q$ with generator $g$ and for uniformly and independently chosen $a,b \in \mathbb{Z}_q$, it should computationally infeasible to determine whether $g^c = g^{ab}$.

Interestingly, this assumption does not hold in the multiplicative
group $\mathbb{Z}_{p}^*$ where $p$ prime ([DDH Wiki](https://en.wikipedia.org/wiki/Decisional_Diffie%E2%80%93Hellman_assumption), [Breaking DDH](https://ellipticnews.wordpress.com/2020/02/14/breaking-the-decisional-diffie-hellman-problem-for-class-group-actions-using-genus-theory/)).


## Approach
The challenge is as follows: We are given [casino.py](./challenge-files/casino.py), which initialises our balance to 100
dollars and will only hand us the flag if we achieve a balance of
200 dollars by playing a binary roulette. For each round won we
will get 1 dollar, for each lost we get 1 dollar deducted.

The roulette is based on DDH, where given $g^a$, $g^b$, $g^c$
we have to guess whether $g^c = g^{ab}$. The casino
establishes a multiplicative group modulo $p$ with $g = 11$, 
thus certain mathematical properties can be exploited to
make accurate predictions.

## Background
The [_Legendre Symbol_](https://en.wikipedia.org/wiki/Legendre_symbol)  is a function defined as follows:

```math
    \left( \frac{g}{p} \right) = \begin{cases}
                1  & \text{if } g \text{ is a quadratic residue modulo } p \text{ and } g \not\equiv_p 0 \\
                -1 & \text{if } g \text{ is a quadratic nonresidue modulo } p \\
                0 & \text{if } g \equiv_p 0
    \end{cases}
```

Coincidentally, it is also multiplicative: 

```math
    \left( \frac{g^a}{p} \right) = \left( \frac{g}{p} \right)^a
```

Since in our case $\left( \frac{g}{p} \right) = -1$, we can directly
infer whether a is odd or even. Thus, given $g^a$, $g^b$ and $g^c$ we first compute the _Legendre_ values of $g^a$, $g^b$. If both $a$ and $b$ are odd, then we know that $ab$ must also be odd, otherwise
$ab$ is even. We can therefore derive the Legendre value of

```math
    \left( \frac{g^{ab}}{p} \right) = \left( \frac{g}{p} \right)^{ab} = (-1)^{ab} = \begin{cases}
                -1  & \text{if both } a,b \text{ odd, i.e.\ } \left( \frac{g^{b}}{p} \right) = \left( \frac{g^{a}}{p} \right) = -1\\
                1 & \text{otherwise}
    \end{cases}
```
If the Legendre value of $g^c$ does not match, then we known for certain that $g^c \neq g^{ab}$.


## Flag
``CSCG{I_should_have_used_prime_order_groups_instead}``