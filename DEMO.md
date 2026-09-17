"TRUSTVEX is a website trust and risk intelligence platform. It's not a
URL checker that returns 'safe' or 'malicious' — it collects evidence
from six independent sources, weights each signal, and shows its
reasoning. I'll scan three URLs in about three minutes and show you what
that looks like in practice."

## Scan 1 — benign URL (1 minute)

Scan: `https://www.wikipedia.org`

Point out:
- Trust score 98/100, "Low observed risk"
- Only risk factor: missing CAA record (a LOW signal)
- Every analyzer at 100% confidence
- URLhaus: NO RESULTS — "this means URLhaus has no record of this URL,
  not that Wikipedia is safe"
- ML prediction: low probability, produced by `trustvex-url-rf-v1`
- Feature vector: 45 features, all populated

"Notice that the report doesn't say 'safe.' It says 'no significant risk
indicators found.' That distinction matters — automated analysis can
never guarantee safety."

## Scan 2 — suspicious-shaped URL (1 minute)

Scan: `https://example.com/login/verify?account=secure&update=1`

Point out:
- Same domain (example.com), same rules apply
- Rule engine fires a HIGH risk factor for the suspicious keywords
- Trust score drops to 83/100
- ML prediction jumps dramatically (98.5%)
- "The ML model has learned that URLs shaped like this — long path,
  many keywords, query parameters — are correlated with labeled
  phishing URLs in its training data."

"This is the key insight: the rule engine and the ML model are two
independent signals. The rule engine says 'five keywords, minus fifteen
points.' The ML model says 'this URL's feature combination looks like
phishing URLs I've seen.' They're answering different questions."

## Scan 3 — real threat (30 seconds, optional)

Scan: A URL currently listed on `https://urlhaus.abuse.ch/browse/`.

Point out:
- URLhaus returns SUSPICIOUS with a threat type and reference link
- HIGH risk factor fires with the URLhaus reference
- "This is live threat intelligence — the URL I scanned is on URLhaus's
  public blocklist right now."

**Do not scan a live malicious URL if you're not comfortable handling
one. If you'd rather skip this, skip it. The first two scans already
demonstrate the architecture.**

## Close (30 seconds)

"What I want to highlight is the honesty of the design. The report
never says 'safe' or 'malicious' — it says 'low observed risk' or
'high observed risk.' When a data source fails, the report says so and
lowers confidence. When the ML model can't be reached, the report says
'unavailable' rather than defaulting to a guess. And the ML model's
own metrics are mediocre — F1 of 0.66 — and reported as such. That's
the difference between a security tool and a security demo."

## If asked...

**"How did you train the model?"**
"A Kaggle phishing URL dataset, 549k rows. I canonicalized and
deduplicated them, capped both classes at 20,000, and split by
registrable domain using the Public Suffix List — no domain appears in
two splits. Trained a RandomForest with fixed hyperparameters, no
grid search. Test F1 was 0.66, ROC-AUC 0.77. The full pipeline is in
`ml/datasets/` and `ml/training/`."

**"Why not combine the rule score and ML score?"**
"Because they measure different things and I don't have a validated
calibration method. Combining them without proper validation would
produce a number that's harder to interpret and easier to fool. I'd
rather keep them separate and honest."

**"What's the biggest limitation?"**
"The ML model sees only 12 URL-string features. It doesn't know if the
site has a valid certificate, or if the redirect chain goes to another
domain, or if the page contains a login form. The rule engine handles
those signals. The ML model is a narrow, complementary signal, not a
replacement for the multi-signal analysis."