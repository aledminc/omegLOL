// Editable moderation word lists — the ONE place to curate terms. The matching LOGIC lives in
// moderation.mjs (word-boundary + leet-folded, so "h4te" is caught and "Scunthorpe" is not).
//
// These are STARTER lists. Before scaling, replace/augment with a maintained source (e.g. the
// `obscenity` npm package, Google's `bad-words` list, or an internal curated list) — keep the
// additions here so policy stays in one file. Terms are compared lowercased.

// Hate slurs / severe terms. HARD-BLOCKED in chat (message dropped) and rejected in usernames.
// Matched on word boundaries AND on a separator-stripped form, so "s-l-u-r" evasion is caught.
// Keep this list specific; do not add ordinary profanity here (that belongs below).
export const SLURS = [
  "nigger", "nigga", "faggot", "chink", "spic", "kike", "gook", "coon",
  "tranny", "retard", "wetback", "beaner", "raghead",
];

// Ordinary profanity. In chat this is REDACTED (replaced with asterisks), not blocked, so adult
// banter still flows; in usernames it is rejected. Matched on word boundaries only (no substrings,
// so "class"/"Scunthorpe"/"assassin" are never touched).
export const PROFANITY = [
  "fuck", "shit", "bitch", "cunt", "asshole", "dick", "pussy", "bastard", "whore", "slut", "cock",
];

// Reserved / impersonation-prone names (usernames only). Compared after leet-folding and stripping
// separators/trailing digits, so "adm1n", "admin_", and "admin1" are all rejected too.
export const RESERVED = [
  "admin", "administrator", "mod", "moderator", "staff", "support", "system", "sys", "root",
  "owner", "official", "omeglol", "help", "helpdesk", "security", "team", "bot",
  "null", "undefined", "anonymous", "everyone", "here",
];
