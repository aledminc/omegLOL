// Pure rating math. No database, no network — just numbers in, numbers out.

// Probability that A beats B given their ratings (the "expected score", 0..1).
export function expectedScore(rA, rB) {
  return 1 / (1 + 10 ** ((rB - rA) / 400));
}

// Turn raw in-game laugh points into A's Elo result: 1 win, 0.5 draw, 0 loss.
export function resultFromScores(scoreA, scoreB) {
  if (scoreA > scoreB) return 1;
  if (scoreA < scoreB) return 0;
  return 0.5;
}

// New ratings after a game. resultA is A's Elo result (1 / 0.5 / 0).
// K is the volatility factor — bigger K = ratings move faster.
export function updatedRatings(rA, rB, resultA, K = 32) {
  const eA = expectedScore(rA, rB);
  const newA = Math.round(rA + K * (resultA - eA));
  const newB = Math.round(rB + K * ((1 - resultA) - (1 - eA)));
  return { a: newA, b: newB };
}
