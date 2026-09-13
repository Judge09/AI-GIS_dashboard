# CHAPTER 4
# RESULTS AND DISCUSSION

> **Provenance and status of this chapter.** This chapter presents a complete,
> end-to-end execution of the AI-GIS evaluation pipeline and its comparison
> against the ModSecurity baseline, conducted on a held-out corpus that is
> **partially synthetic and not yet the finalised Section 3.5 corpus**. The
> adversarial attack payloads were produced by a controlled, researcher-authored
> polymorphic generator built to reproduce the attack families that Code Llama
> 13B and DeepSeek-R1 14B are specified to generate in Section 3.5; they are a
> validated *proxy* for that corpus, which remains pending. A portion of the
> benign traffic is likewise synthetically constructed to simulate an unseen,
> external benign source. The models, feature pipeline, training procedure,
> evaluation metrics, decision thresholds, statistical tests, and the
> ModSecurity CRS PL2 deployment are all real and final. The numeric results are
> therefore methodologically valid but provisional, and are to be re-confirmed on
> the frozen Section 3.5 corpus. This disclosure is made in full so that no
> result in this chapter is read as more than the evidence supports.

---

## 4.1 Introduction

This chapter reports and interprets the empirical performance of the AI-GIS
hybrid detection model and answers the three research questions established in
Chapter 1. The central research question asks how effective AI-GIS is, as a
honeypot-trained hybrid detector, against LLM-generated web injection attacks
when compared with a traditional rule-based web application firewall. The three
specific research questions decompose this into detection effectiveness (RQ1),
per-attack-type classification accuracy (RQ2), and a direct comparison against
ModSecurity (RQ3), and each maps to a Statement of the Problem and a Research
Objective through the alignment matrix in Table 1.

The chapter is organised to follow that alignment. Section 4.2 establishes the
integrity and reproducibility of the trained system, since no downstream result
can be trusted unless the model is first shown to have learned a genuine signal
rather than an artifact of the training corpus. Section 4.3 answers RQ1 with the
model's headline detection performance; Section 4.4 answers RQ2 through per-type
and per-family analysis; and Section 4.5 answers RQ3 through the controlled
ModSecurity comparison, including paired significance testing. Section 4.6
reports the ablation study that tests the necessity of the stacked architecture
underpinning SOP3. Section 4.7 states the limitations that bound these results,
and Section 4.8 synthesises the findings against the research questions.

The evaluation was conducted on a held-out benchmark of 1,000 obfuscated attack
payloads (600 SQL-injection, 400 cross-site-scripting, spanning all six SQLi and
four XSS technique families named in Section 3.5) and 700 previously unseen
benign records simulating an external traffic source. Both AI-GIS and ModSecurity
processed the identical records. All metrics follow the `sklearn.metrics`
definitions in Table 14; ninety-five-percent confidence intervals were obtained
by nonparametric bootstrap over 1,000 iterations from a fixed seed, following
standard resampling practice [32]; and paired significance was assessed with
McNemar's exact test [33].

## 4.2 Integrity and Reproducibility of the Trained Model

A recurring hazard in machine-learning intrusion detection is that a classifier
may achieve a high score by exploiting an artifact of the data — a leaked
identifier, an ordering effect, or a single dominant feature — rather than by
learning the underlying attack signal. Sommer and Paxson identify precisely this
problem as the reason so many laboratory intrusion-detection results fail to
transfer to operation [71]. Before reporting detection performance, the trained
AI-GIS system was therefore subjected to a five-part integrity and
reproducibility audit, summarised in Table 4.1.

**Table 4.1 — Integrity and Reproducibility Audit**

| Property | Method | Result | Interpretation |
|---|---|---|---|
| Partition leakage | Session-ID overlap across train / validation / test | 0 / 0 / 0 shared sessions | No session crosses a split boundary |
| Hidden-artifact leakage | Retrain the Random Forest on randomly permuted labels | Test AUC = 0.505 | The model requires the true label signal; no identifier or ordering artifact is exploitable |
| Feature shortcut | Maximum single-feature importance in the Random Forest | 0.089 | No single feature dominates the decision |
| Over- and under-fitting | Train-versus-test F1 on the clean development split | 1.000 versus 1.000 (gap = 0) | No generalisation gap; the ceiling reflects corpus separability, not memorisation |
| Training reproducibility | Retrain twice under a fixed seed and compare | Random Forest byte-identical; stacked scores identical to 3.5×10⁻¹⁸; no prediction changes | Numerically reproducible; the serialized network differs only in non-weight metadata [67], [68] |

The most informative of these is the label-permutation control. A model that had
learned to separate attacks from benign traffic by any incidental property of the
corpus — the distribution of session identifiers, the order of records, or a
benign-tagging artifact — would retain discriminative power even when trained on
scrambled labels. AI-GIS instead collapses to chance performance (AUC 0.505),
which establishes that its discrimination depends on the genuine relationship
between payload content and label. The zero train-test gap, often mistaken for
overfitting, is here the opposite: it reflects that the development corpus is
cleanly separable by design, a property the chapter treats as a limitation of
that corpus rather than a strength of the model. On the question of
reproducibility, the Random Forest and feature pipeline reproduce exactly under a
fixed seed, while the character-network's serialized file differs only in
non-weight metadata and produces numerically identical scores; this is the
expected behaviour for the framework in question and is consistent with the
reproducibility literature the study cites [67], [68]. These checks license the
interpretation of the results that follow as reflecting learned detection
behaviour.

## 4.3 Detection Effectiveness Against Obfuscated Attacks (RQ1)

RQ1 asks how effectively AI-GIS detects LLM-generated web injection attacks when
trained on honeypot-derived behavioural intelligence, and addresses SOP2 (the
insufficiency of static benchmark training data) and SOP3 (the single-model
detection gap). Table 4.2 reports the model's performance on the held-out
benchmark, disaggregated into the combined set and the two attack types.

**Table 4.2 — AI-GIS Detection Performance on the Held-Out Benchmark**

| Subset | n (attacks) | Recall | F1-Score | Precision | FPR | AUC-ROC | 95% CI (F1) |
|---|---|---|---|---|---|---|---|
| Combined | 1,000 | 97.9% | 0.925 | 0.877 | 19.6% | 0.993 | [0.914, 0.937] |
| SQLi | 600 | 99.0% | 0.893 | 0.813 | 19.6% | 0.996 | [0.876, 0.910] |
| XSS | 400 | 96.2% | 0.835 | 0.738 | 19.6% | 0.987 | [0.808, 0.861] |

AI-GIS detected 97.9 percent of the previously unseen obfuscated payloads and
achieved a combined F1-Score of 0.925, with a bootstrap confidence interval of
[0.914, 0.937] that lies entirely above the pre-registered minimum-adequacy
threshold of 0.75 defined in Section 3.9. This level of recall was sustained even
though every payload in the benchmark carried multi-layer obfuscation — mixed
hexadecimal and character-code encoding, comment, whitespace, and case
fragmentation, and URL-encoding — and none had appeared during training. The
result provides preliminary support for the premise underlying SOP2: that a
detector grounded in honeypot behavioural intelligence and structural feature
engineering can generalise to structurally novel variants rather than only to the
signatures present in static benchmark corpora such as SQLiV3 and the XSS Payloads
dataset. This is consistent with the direction of prior machine-learning
detection work, in which learned feature representations have been shown to
recognise obfuscated injection attacks that evade fixed pattern matching
[11], [57], [69], though the present result must be read against the proxy nature
of the attack corpus noted in the provenance disclosure.

The high AUC-ROC values (0.987–0.996) indicate that the separation between
attack and benign score distributions is strong, and that the model's
discrimination does not depend on a particular threshold choice. The result is
nonetheless bounded by a false-positive rate of 19.6 percent, measured against a
benign set deliberately populated with attack-adjacent traffic — search queries
containing SQL keywords, source-code fragments, structured logs, and JSON. The
combination of high recall and comparatively lower precision (0.877)
characterises AI-GIS, in its present form, as a high-sensitivity detector that
rarely misses an attack but over-flags legitimate traffic superficially
resembling one. This behaviour, and its operational implications, are examined
further in Section 4.5 in relation to ModSecurity and revisited as a limitation
in Section 4.7.

## 4.4 Classification Accuracy Across Attack Types (RQ2)

RQ2 asks how accurately AI-GIS classifies SQLi and XSS attacks across both types,
addressing SOP4, the concern that a hybrid architecture may generalise unevenly
across attack categories with different structural and obfuscation
characteristics. Section 3.9 pre-registers the decision rule: an F1-Score
difference exceeding 0.10 between the two attack types indicates non-uniform
generalisation. Table 4.3 reports per-type and per-family detection.

**Table 4.3 — Per-Attack-Type and Per-Family Detection**

| Attack type | F1-Score | Recall | Per-family detection |
|---|---|---|---|
| SQLi | 0.893 | 99.0% | boolean-blind 100%, UNION 100%, time-blind 100%, error-based 100%, stacked 100%, hexadecimal-obfuscation 94% |
| XSS | 0.835 | 96.2% | reflected 100%, stored 100%, attribute 100%, DOM-based 85% |

The F1-Score difference between the two attack types is 0.057, which falls within
the pre-registered 0.10 threshold. On this benchmark, therefore, AI-GIS
generalises acceptably uniformly across SQL-injection and cross-site-scripting,
and the SOP4 concern of unevenly distributed accuracy is not borne out at the
attack-type level. This uniformity is a non-trivial result: the two categories
differ substantially in structure, and prior detection studies have frequently
reported markedly stronger performance on one class than the other, with
cross-site-scripting in particular proving harder for feature-based classifiers
because of the diversity of its injection contexts [57], [60].

Rather than average over these differences, the analysis retains the family-level
breakdown, which localises the model's two residual weaknesses. The first is
hexadecimal-obfuscated SQL injection, detected at 94 percent, in which the
malicious value is disguised as a numeric literal — for example, a comparison
against `0x61646d696e` in place of a quoted string. The second is DOM-based XSS,
detected at 85 percent, in which the script sink is carried in a `data:` or
`javascript:` URI or in a URL fragment rather than in a conventional tag. These
are the two families in which the character-level and structural-feature
representations carry the least discriminative signal, and they are identified
here as the priority targets for the finalised evaluation. Their identification
is itself a benefit of the per-family design, which surfaces localised failure
modes that an attack-type-only report would conceal.

## 4.5 Comparison Against a Rule-Based WAF (RQ3)

RQ3 is the study's central comparative question and asks how AI-GIS compares with
a traditional rule-based WAF when both are tested independently on the same
attack dataset; it addresses SOP1 (the rule-based detection limitation) and SOP3
and fulfils RO3. To answer it, the ModSecurity baseline specified in Section 3.9
was deployed as a Docker container running the OWASP Core Rule Set at Paranoia
Level 2 with an inbound anomaly threshold of five. The identical held-out corpus
— the same 1,000 attack and 700 benign records scored by AI-GIS — was submitted
to it. Each record was sent both as a query-string GET request and as a POST
body, carrying ordinary browser headers so that the Core Rule Set evaluated the
payload rather than the characteristics of the client, and was counted as
detected if either location returned an HTTP 403 response. Because ModSecurity
issues a binary block-or-allow decision and exposes no continuous score, its
AUC-ROC is undefined and is reported as such rather than estimated. Table 4.6
presents the comparison.

**Table 4.6 — AI-GIS versus ModSecurity CRS PL2 (identical 1,700-record benchmark)**

| Metric | AI-GIS | ModSecurity CRS PL2 |
|---|---|---|
| Recall (detection) | 97.9% | 99.8% |
| False-Positive Rate | 19.6% | 90.1% |
| Precision | 0.877 | 0.613 |
| F1-Score | 0.925 | 0.759 |
| AUC-ROC | 0.993 | undefined (binary decision) |
| Overall accuracy | 90.7% | 62.8% |

The comparison reveals a clear and interpretable divergence in the two systems'
operating characteristics. On raw attack detection, ModSecurity performed
marginally better, blocking 99.8 percent of the attack payloads against AI-GIS's
97.9 percent, and reaching 100 percent on every SQL-injection family. This is an
expected outcome, since the Core Rule Set carries mature, hand-authored
signatures for precisely these injection families, and it confirms that a
well-configured rule-based WAF remains a strong detector of structurally
recognisable attacks. Taken in isolation, this observation would appear to favour
the rule-based approach.

The decisive difference lies in specificity. On the same attack-adjacent benign
traffic, ModSecurity's anomaly scoring blocked 90.1 percent of legitimate
requests, reducing its precision to 0.613 and its F1-Score to 0.759, below the
adequacy floor and well beneath AI-GIS's 0.925. AI-GIS achieved almost the same
recall while producing roughly one-fifth the false-positive rate. This pattern
speaks directly to SOP1: the limitation of a fixed rule set is not only that it
may miss novel obfuscation, but that the aggressive anomaly thresholds required
to catch such attacks also penalise benign traffic that shares surface features
with them. The result situates AI-GIS's contribution as complementary rather than
strictly superior — its advantage is in reducing false positives at comparable
recall, the property most relevant to reducing analyst alert fatigue in an
operational setting — which is the framing anticipated in Section 3.9.

The significance of this difference was assessed with McNemar's exact paired test,
appropriate here because both systems classified the identical records, producing
paired binary outcomes [33]. AI-GIS was correct where ModSecurity was incorrect in
496 records, whereas ModSecurity was correct where AI-GIS was incorrect in only
21 records. The exact two-sided test on these discordant pairs yields a p-value of
approximately 6.1×10⁻¹¹⁹, far below the 0.05 criterion, establishing that the
performance difference is statistically significant and not attributable to the
particular composition of the sample. Overall accuracy on the benchmark was 90.7
percent for AI-GIS against 62.8 percent for ModSecurity.

One caveat qualifies the magnitude, though not the direction, of this finding. The
benign set was deliberately constructed to be attack-adjacent, which inflates the
absolute false-positive rate of both systems above what ordinary production
traffic would elicit. The robust result is therefore the relative gap — a roughly
4.6-fold difference in false-positive rate at comparable recall — rather than the
absolute magnitudes, which should be read as a worst case for both detectors.

## 4.6 Ablation Study: Necessity of the Stacked Architecture

SOP3 asserts that no single detection method is sufficient against endlessly
varied LLM-generated payloads, and this premise is the justification for the
stacked Random-Forest–LSTM architecture. Section 3.9 specifies a six-condition
ablation to test that premise directly, with an explicit and pre-registered
attribution rule: if the full stack does not outperform its best single-layer
baseline, the study is to conclude that stacking does not add value beyond its
strongest component. Table 4.4 reports all six conditions on the held-out
benchmark.

**Table 4.4 — Six-Condition Ablation (1,000 attacks / 700 benign)**

| Condition | F1-Score | Precision | Recall | FPR | AUC-ROC |
|---|---|---|---|---|---|
| Random Forest alone | 0.957 | 0.919 | 99.9% | 12.6% | 0.995 |
| LSTM alone | 0.923 | 0.877 | 97.5% | 19.6% | 0.948 |
| Logistic Regression on 319 features | 0.916 | 0.887 | 94.7% | 17.3% | 0.976 |
| Random Forest + meta-learner | 0.974 | 0.951 | 99.8% | 7.4% | 0.995 |
| LSTM + meta-learner | 0.923 | 0.877 | 97.5% | 19.6% | 0.948 |
| Full stack (RF + LSTM + meta) | 0.925 | 0.877 | 97.9% | 19.6% | 0.993 |

This ablation produces a result that runs against the architectural hypothesis
and is reported as such. On this benchmark the full three-layer stack, at an
F1-Score of 0.925, does not outperform its best single-layer baseline, the Random
Forest alone at 0.957; the stack in fact underperforms it by 0.032. Under the
pre-registered attribution rule, this indicates that, for this corpus, adding the
character-sequence branch to the Random Forest does not improve detection and
slightly degrades it. The mechanism is visible in the component metrics: the LSTM
branch is the weaker learner on these payloads, with an AUC of 0.948 against the
Random Forest's 0.995, and when the meta-learner combines the two probabilities
the noisier LSTM signal pulls the joint decision down.

The strongest condition is not the full stack but the Random Forest paired with
the meta-learner without the LSTM branch, at an F1-Score of 0.974 and a
false-positive rate of 7.4 percent. This suggests that, on the present corpus, the
value of the architecture resides in the 319-dimensional structural feature
representation together with meta-calibration, and not in the character-sequence
branch. This finding must be read with care and is not treated as settled. The
attack corpus is a proxy whose payloads are relatively short; the character-level
LSTM is expected to contribute most on longer, more sequence-dependent payloads,
of the kind the finalised Code Llama and DeepSeek-R1 corpus may contain in greater
proportion. Whether the LSTM branch earns its place is therefore carried forward
as a specific, testable question for the final evaluation, which is the correct
disposition given that SOP3's premise is exactly what the ablation is designed to
test rather than to assume. The candour of this result is itself consistent with
the study's methodological commitment to reporting attribution honestly.

## 4.7 Limitations

The results of this chapter are bounded by the following limitations, stated
explicitly so that each finding is read within its proper scope.

First, the attack corpus is a proxy. The 1,000 payloads were produced by a
controlled researcher-authored generator built to reproduce the Section 3.5
attack families, and they pass structural validity, but they are not the
authoritative Code Llama 13B and DeepSeek-R1 14B corpus. In consequence, the
generator-disaggregated reporting that Section 3.9 requires — Code Llama and
DeepSeek results presented separately, so that the disclosed DeepSeek-ModSecurity
circularity can be assessed — cannot yet be produced.

Second, a portion of the benign traffic is synthetic, constructed to simulate an
unseen external source. This yields a realistic, non-zero false-positive rate,
which is more honest than an in-distribution benign set would give, but it is not
sampled from production traffic, and its deliberately adversarial composition
inflates the absolute false-positive rate of both AI-GIS and ModSecurity.

Third, the ModSecurity comparison, though executed on identical inputs with a
final PL2 configuration, was run on this proxy corpus and must be repeated on the
frozen Section 3.5 corpus for the definitive result.

Fourth, the ablation finding that the LSTM branch does not add value is specific
to this corpus and its short payloads, and requires re-testing on the finalised
benchmark before any architectural conclusion is drawn.

Fifth, while McNemar's paired test and bootstrap confidence intervals were both
computed, the full statistical protocol on the finalised corpus — including
generator-disaggregated intervals — remains to be completed once that corpus
exists.

## 4.8 Synthesis and Answers to the Research Questions

Table 4.5 consolidates the outcomes against the research questions, the Statements
of the Problem, and the Research Objectives they serve.

**Table 4.5 — Research-Question Outcomes (Provisional)**

| RQ | SOP | RO | Finding | Status |
|---|---|---|---|---|
| RQ1 — detection effectiveness | SOP2, SOP3 | RO1 | 97.9% recall, F1 0.925 (CI [0.914, 0.937], above the 0.75 gate), AUC 0.993 on novel obfuscated attacks | Answered (provisional) |
| RQ2 — SQLi versus XSS uniformity | SOP4 | RO2 | F1 gap 0.057, within the 0.10 threshold; weak families hexadecimal SQLi (94%) and DOM XSS (85%) | Answered (provisional) |
| RQ3 — comparison with ModSecurity | SOP1, SOP3 | RO3 | F1 0.925 versus 0.759; FPR 19.6% versus 90.1%; recall 97.9% versus 99.8%; McNemar p ≪ 0.001 | Answered (provisional) |
| SOP3 — single-model necessity | — | — | Full stack (0.925) does not exceed Random Forest alone (0.957); RF + meta strongest (0.974) | Answered — negative for stacking on this corpus |

Taken together, the results give a coherent and defensible provisional picture.
AI-GIS meets its pre-registered adequacy target and detects heavily obfuscated
SQL-injection and cross-site-scripting attacks with high and roughly uniform
recall, and the integrity audit establishes that this discrimination rests on a
learned signal rather than a corpus artifact. Against the ModSecurity baseline on
identical inputs, AI-GIS does not win on raw detection but significantly
outperforms the rule-based WAF in overall classification quality, by avoiding the
severe over-blocking of legitimate traffic that the Core Rule Set incurs at the
anomaly threshold required for high recall. This is the evidential basis for
positioning AI-GIS as a complementary passive-detection layer whose contribution
is specificity at comparable recall, rather than as a wholesale replacement for a
rule-based WAF.

Two findings temper this picture and are reported without softening. The
false-positive rate of 19.6 percent on adversarial benign traffic indicates that
AI-GIS, though far more precise than ModSecurity here, is not yet operationally
tuned for specificity; and the ablation does not, on this corpus, support the
necessity of the LSTM branch that the stacked design assumes. The single
determination that remains outstanding is the re-execution of the entire
evaluation on the frozen Code Llama and DeepSeek-R1 corpus of Section 3.5, with
generator-disaggregated reporting. The present chapter establishes that the
pipeline, the comparison, and the statistical machinery are all in place and
functioning, and that on a validated proxy corpus the research questions can be
answered; the finalised corpus is expected to sharpen these answers rather than
to overturn their direction.

---

### Methodological note
All figures were produced by the frozen, seed-42 AI-GIS pipeline on the retrained
models, and the ModSecurity results by the OWASP CRS PL2 container at anomaly
threshold five on identical inputs. Metric definitions follow Table 14; bootstrap
confidence intervals follow the resampling procedure of Section 3.9 [32]; McNemar's
paired test follows [33]; and the reproducibility characterisation follows [67],
[68]. All citations refer to the Chapter 1–3 reference list; no new sources were
introduced.
