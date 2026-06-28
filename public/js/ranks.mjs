// Elo -> comedy rank tiers. Rank is a pure view of rating, computed client-side.
export const TIERS = [
  { name: "Silver Snickerer",  min: 0,    color: "#b9c2c9" },
  { name: "Gold Giggler",      min: 1100, color: "#e8b94e" },
  { name: "Platinum Parodist", min: 1250, color: "#7fd6e0" },
  { name: "Diamond Droll",     min: 1400, color: "#8ea2ff" },
  { name: "Comedian",          min: 1550, color: "#c77dff" },
  { name: "True Jester",       min: 1700, color: "#ff5aa0" },
];
export function rankFor(rating) {
  let t = TIERS[0];
  for (const tier of TIERS) if (rating >= tier.min) t = tier;
  return t;
}
export function rankRange(i) {
  const next = TIERS[i + 1];
  return next ? `${TIERS[i].min} – ${next.min - 1}` : `${TIERS[i].min}+`;
}
