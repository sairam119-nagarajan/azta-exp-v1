# Evidence-fusion ablation (counterfactual replay of the formal Shadow-Mode traces)

Removed components dropped, remaining frozen weights renormalised; τ_Q 65, τ_R 75, λ 0.1, N = 2 unchanged. Liveness-only is the recorded rule output. Identity revocations come from the recorded active device02 sessions (hard gate). Never enforced.

| Variant | Weights α/β/γ (renormalised) | A* R / Q | FPR | Recall | F1 | Behavioural episodes N=1 / N=2 (of 225) | False requests /1k benign | Context windows F/R/Q (of 135) | Context episodes detected (of 5) | Silence episodes (of 5) | Identity revocations (of 5) |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Identity only | 1/0/0 | n/a / n/a | 0.00% | 0.00% | n/a | 0 / 0 | 0.00 | 135/0/0 | 0 | 0 | 5/5 |
| Autoencoder (behaviour) only | 0/1/0 | 2.88 / 4.31 | 1.68% | 97.63% | 0.941 | 197 / 191 | 1.97 | 129/2/4 | 2 | 2 | 0/5 |
| Liveness/timing rule only (recorded) | recorded rule | n/a / n/a | 0.00% | 0.00% | n/a | 0 / n/a | n/a | n/a | 0 | 5 | 0/5 |
| Identity + Behaviour | 0.286/0.714/0 | 4.31 / 6.73 | 1.08% | 97.15% | 0.955 | 197 / 188 | 1.97 | 131/1/3 | 2 | 2 | 5/5 |
| Identity + Context | 0.4/0/0.6 | n/a / n/a | 0.00% | 0.00% | n/a | 0 / 0 | 0.00 | 0/3/132 | 5 | 0 | 5/5 |
| **Full AZTA (Identity + Behaviour + Context)** | 0.2/0.5/0.3 | 6.93 / 12.04 | 0.71% | 96.42% | 0.961 | 197 / 187 | 1.97 | 3/125/7 | 5 | 2 | 5/5 |
