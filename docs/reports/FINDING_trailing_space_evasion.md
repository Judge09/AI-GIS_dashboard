# Finding: trailing-whitespace evasion defeats the stacked ensemble

Discovered 2026-08-26 while evaluating whether a BiLSTM would improve the model.

## Result

Appending 40 space characters to a payload drops detection on the **real**
LLM holdout corpus (`data/eval/llm_holdout_full.csv`, 78 attacks):

| input                | LSTM detected | Stacked detected |
|----------------------|---------------|------------------|
| bare                 | 74 / 78       | 74 / 78          |
| + 40 trailing spaces | 2 / 78        | **2 / 78**       |

72 payloads flip from detected to missed. Examples:

    <script>alert(1)</script>          lstm 1.000 -> 0.000
    1' UNION SELECT ... FROM users--   lstm 1.000 -> 0.000
    ' OR 1=1                           lstm 0.995 -> 0.000

RF v2 is unaffected (0.99 -> 0.98) because its features are aggregate counts.
The meta-learner still weights the collapsed LSTM enough to push the stacked
score under 0.5, so the ensemble fails as a whole.

## Mechanism

`ordinal_encode()` maps space to 32. `Embedding(mask_zero=True)` masks only the
0 pad, so trailing spaces are **real timesteps**. The final LSTM state is read
after them, and the attack signal is washed out.

It is specific to the space character:

    bare        lstm=0.9972
    +40 spaces  lstm=0.0001
    +40 tabs    lstm=0.9998
    +40 letters lstm=1.0000

## Root cause

Trailing spaces occur in **0.0% of training rows, in both classes**
(`data/prepared/lstm_train.npz`, sampled 4000/class). Padded input is therefore
out of distribution — this is an unconstrained region of input space, not a
learned "spaces = benign" rule.

`scripts/text_normalize.py::normalize_text()` does not strip, so the padding
reaches the encoder at inference.

## Fix

Stripping before encoding fully restores the score:

    +40 spaces, stripped -> lstm=0.9972   (identical to bare)

Recommended, in order:
1. `.strip()` in `normalize_text()` — one line, restores all 72 payloads.
   Must be applied to training and inference together, then models retrained,
   or train/serve skew is introduced.
2. Add whitespace-padded variants to training augmentation so the region is
   covered rather than merely avoided.
3. Consider collapsing internal whitespace runs, which is the same evasion
   with `%09`/`%0a` instead of spaces.

## Padding position (measured)

The evasion is symmetric, so it is not a property of the forward pass:

| variant             | LSTM detected |
|---------------------|---------------|
| bare                | 74 / 78       |
| trailing 40 spaces  | 2 / 78        |
| **leading** 40 sp   | 8 / 78        |
| 20 leading + 20 trailing | 1 / 78   |
| trailing, stripped  | 74 / 78       |

## Note on BiLSTM

A bidirectional LSTM does **not** fix this. The measurements above show leading
padding is nearly as effective as trailing (8/78 vs 2/78), so a backward pass
is defeated by the same trick mirrored. Fix the preprocessing first, then
re-measure whether the architecture change still buys anything.
