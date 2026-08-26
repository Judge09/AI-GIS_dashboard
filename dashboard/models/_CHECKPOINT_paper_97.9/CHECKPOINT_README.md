# AI-GIS CHECKPOINT — paper-matching model (do not overwrite)

This is the frozen model that produced the results reported in **AIGIS_Paper.docx**.
If models/ is ever mangled or retrained, restore from here.

## Verified results (held-out benchmark: 1000 attacks / 700 benign)
- Detection (recall): 97.9%
- F1-Score: 0.9253   (95% CI [0.914, 0.937])
- Precision: 0.8772
- False-Positive Rate: 19.6%
- AUC-ROC: 0.9926
- SQLi F1: 0.893   XSS F1: 0.835   (gap 0.057, within 0.10)
- McNemar vs ModSecurity: p ~ 6.1e-119

## File fingerprints (SHA-256)
rf2.pkl               08aff449c01470bdea7dbb2546f7cb53ecccd194f9ad0ff65aef699739136899
meta.pkl              49fdec026e05bda6b98d08e1ff0e6cff419e36ae4d178c777412223e7302390e
lstm_best.keras       3216f0b91767379a04e7844e0a00de6b32cfeaa178cd6723640aafdec85dbbff
ngram_vectorizer.pkl  2b74ed700968c0326a4318e529f3bb0f99bfc9facbeef1653067e03d77d5a268

## To restore this checkpoint into models/
cp models/_CHECKPOINT_paper_97.9/*.pkl    models/
cp models/_CHECKPOINT_paper_97.9/*.keras  models/

## To verify a model is the checkpoint
sha256sum models/rf2.pkl   # must start with 08aff449c01470bd
