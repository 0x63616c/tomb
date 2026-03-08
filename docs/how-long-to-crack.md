# How Long Would It Take to Crack a 21-Word Passphrase?

*In the style of xkcd's "what if?"*

---

## The Question

> I encrypted a file with a 21-word diceware passphrase, two chained key derivation functions, and three layers of encryption. How long would it take to crack?

## The Setup

The passphrase is 21 randomly chosen words from a list of 7,776 words (the EFF diceware list). Each word adds log2(7776) = 12.925 bits of entropy.

21 words x 12.925 bits = **271.4 bits of entropy**.

That means there are 2^271 possible passphrases. Let's write that out:

**3,800,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000,000**

That's 3.8 x 10^81.

The observable universe contains roughly 10^80 atoms. So the number of possible passphrases is about **38 times the number of atoms in the observable universe**.

If you assigned a different passphrase to every atom in existence, you'd run out of atoms first.

## OK But What If We Guess Really Fast?

Let's say you build a computer that can try one billion passphrases per second. That's fast. That's roughly one guess per clock cycle of a modern CPU.

Time to try all passphrases: 3.8 x 10^81 / 10^9 = 3.8 x 10^72 seconds.

The universe is 13.8 billion years old, which is about 4.35 x 10^17 seconds.

So you'd need **8.7 x 10^54 universe ages**. That's a 55-digit number of universe lifetimes.

Even if you'd started guessing at the Big Bang, you wouldn't be a trillionth of a trillionth of a percent of the way done.

## What If We Use Every Computer on Earth?

Estimates put the combined computing power of every device on the planet at roughly 10^18 operations per second. Let's pretend all of it is dedicated to cracking your passphrase.

3.8 x 10^81 / 10^18 = 3.8 x 10^63 seconds = **8.7 x 10^45 universe ages**.

We shaved nine zeros off! Unfortunately, we still need a number with 45 digits' worth of universe lifetimes.

## OK, What About Quantum Computers?

Grover's algorithm is a quantum search algorithm that can search an unsorted database quadratically faster. It effectively halves the bit security of any brute-force search.

271 bits / 2 = **135.7 bits of effective security** against a quantum computer.

2^135.7 = 6.2 x 10^40 quantum operations needed.

Even with our hypothetical "every computer on Earth" cluster, but quantum:

6.2 x 10^40 / 10^18 = 6.2 x 10^22 seconds = **1.4 x 10^5 universe ages**.

That's 141,000 universe lifetimes. Better! Still not great (for the attacker).

## What If Each Guess Is Free?

So far we've been ignoring something. Each "guess" isn't just checking a passphrase. It requires running scrypt (1GB of RAM) then Argon2id (another 1GB of RAM). In practice, each guess takes about 5 seconds on real hardware and needs a gigabyte of memory.

But let's be extremely generous and say each guess is *instant*. Zero cost. Free. What's the absolute theoretical limit?

### Enter the Planck Time

The Planck time is the smallest meaningful unit of time in physics: 5.39 x 10^-44 seconds. Below this scale, our understanding of physics breaks down. You literally cannot have an event happen faster than one Planck time. It is, as far as we know, the tick rate of reality.

**Classical brute force, one guess per Planck time:**

3.8 x 10^81 x 5.39 x 10^-44 = 2.05 x 10^38 seconds = **4.7 x 10^20 universe ages**

Even checking one passphrase per fundamental tick of the universe, running since the Big Bang, you'd need **470 quintillion** universe lifetimes.

**Grover's algorithm, one operation per Planck time:**

6.2 x 10^40 x 5.39 x 10^-44 = **0.0033 seconds**

Wait. What?

3.3 milliseconds. With a quantum computer operating at the Planck frequency running Grover's algorithm, you'd crack the passphrase in the time it takes a hummingbird to flap its wings once.

Before you panic: a quantum computer operating at Planck frequency would require more energy than the observable universe contains. This machine cannot exist. We're deep into "what if the laws of physics were different" territory.

But it's interesting that there *is* a theoretical scenario where 271 bits isn't enough. So let's ask the next question.

## How Many Bits Would We Need?

Let's set the bar as high as it can go: survive Grover's algorithm running at one operation per Planck time, for longer than the heat death of the universe.

The heat death of the universe, the point at which entropy reaches maximum and nothing interesting can ever happen again, is estimated to occur in about 10^106 years. This is after all stars have burned out (10^14 years), all protons have decayed (10^40 years), and all black holes have evaporated (10^100 years). Everything is cold, dark, and uniform. Time has effectively ended.

**How many Planck times until heat death?**

10^106 years x 3.15 x 10^7 sec/year = 10^113.5 seconds

10^113.5 / 5.39 x 10^-44 = 10^156.8 Planck times

That's about **521 bits** worth of operations.

Since Grover's halves the bits, we need:

521 x 2 = **1,042 bits of entropy**

In diceware words: 1,042 / 12.925 = **81 words**

## The Final Table

| Scenario | Bits | Diceware Words |
|---|---|---|
| Your WiFi password | ~40 | 3 |
| Bitcoin private key | 256 | 20 |
| **tomb (your system)** | **271** | **21** |
| Survive classical @ Planck speed until heat death | 521 | 41 |
| Survive Grover's @ Planck speed until heat death | 1,042 | 81 |

## In Summary

A 21-word diceware passphrase has more possible combinations than atoms in the observable universe. Even a classical computer running at the speed of physics, since the beginning of time, would be nowhere close to finishing. The only theoretical crack involves a quantum computer that cannot physically exist, and even then it only works because we're at "merely" 271 bits.

To make it truly, permanently, cosmologically uncrackable against a Planck-speed quantum computer running until the heat death of the universe, you'd need to type 81 words instead of 21.

But at that point, even on an impossible computer, the passphrase takes longer to type than to crack.

---

*Inspired by [xkcd what if?](https://what-if.xkcd.com/) and the tomb encryption tool.*
