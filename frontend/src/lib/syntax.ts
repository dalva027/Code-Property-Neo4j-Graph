// A small line tokenizer for the source panel: comments, strings, keywords, macros, types,
// attributes and numbers in Rust, Python and TOML. Block comments and multi-line strings carry over
// from one line to the next. It colours code; it does not parse it.

export type TokenKind = "kw" | "str" | "com" | "num" | "mac" | "type" | "attr" | "life" | "fn" | "plain";
export interface Token {
  text: string;
  kind: TokenKind;
}

const RUST_KW = new Set(
  ("as async await break const continue crate dyn else enum extern false fn for if impl in let loop match mod move " +
    "mut pub ref return self Self static struct super trait true type unsafe use where while yield").split(" "),
);
const PY_KW = new Set(
  ("False None True and as assert async await break class continue def del elif else except finally for from global " +
    "if import in is lambda nonlocal not or pass raise return try while with yield self").split(" "),
);

type Mode =
  | { k: "code" }
  | { k: "block"; depth: number }                 // inside /* */ (Rust comments nest)
  | { k: "str"; close: string };                  // inside a string that ends with `close`

const IDENT = /[A-Za-z_][A-Za-z0-9_]*/y;
const NUMBER = /(?:0x[0-9a-fA-F_]+|0b[01_]+|0o[0-7_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)(?:[a-z]\w*)?/y;

function push(out: Token[], text: string, kind: TokenKind) {
  if (!text) return;
  const last = out[out.length - 1];
  if (last && last.kind === kind) last.text += text;
  else out.push({ text, kind });
}

/** Ends a string: returns the index after the closing delimiter, or -1 when it runs past the line. */
function closeString(line: string, from: number, close: string): number {
  for (let i = from; i < line.length; i++) {
    if (line[i] === "\\" && close.length === 1) {
      i++;
      continue;
    }
    if (line.startsWith(close, i)) return i + close.length;
  }
  return -1;
}

function rustLine(line: string, mode: Mode, out: Token[]): Mode {
  let i = 0;
  while (i < line.length) {
    if (mode.k === "block") {
      let depth = mode.depth;
      let j = i;
      for (; j < line.length && depth > 0; j++) {
        if (line.startsWith("/*", j)) { depth++; j++; }
        else if (line.startsWith("*/", j)) { depth--; j++; }
      }
      push(out, line.slice(i, j), "com");
      i = j;
      mode = depth > 0 ? { k: "block", depth } : { k: "code" };
      continue;
    }
    if (mode.k === "str") {
      const end = closeString(line, i, mode.close);
      if (end < 0) { push(out, line.slice(i), "str"); return mode; }
      push(out, line.slice(i, end), "str");
      i = end;
      mode = { k: "code" };
      continue;
    }
    const rest = line.slice(i);
    if (rest.startsWith("//")) { push(out, rest, "com"); break; }
    if (rest.startsWith("/*")) { push(out, "/*", "com"); i += 2; mode = { k: "block", depth: 1 }; continue; }
    const raw = /^b?r(#*)"/.exec(rest);
    if (raw) { push(out, raw[0], "str"); i += raw[0].length; mode = { k: "str", close: `"${raw[1]}` }; continue; }
    const quote = /^b?"/.exec(rest);
    if (quote) { push(out, quote[0], "str"); i += quote[0].length; mode = { k: "str", close: '"' }; continue; }
    const char = /^b?'(?:\\.|\\u\{[0-9a-fA-F]+\}|[^\\'])'/.exec(rest);
    if (char) { push(out, char[0], "str"); i += char[0].length; continue; }
    const life = /^'[A-Za-z_]\w*/.exec(rest);
    if (life) { push(out, life[0], "life"); i += life[0].length; continue; }
    const attr = /^#!?\[[^\]]*\]?/.exec(rest);
    if (attr) { push(out, attr[0], "attr"); i += attr[0].length; continue; }
    NUMBER.lastIndex = i;
    if (/[0-9]/.test(line[i]) && NUMBER.exec(line)) { push(out, line.slice(i, NUMBER.lastIndex), "num"); i = NUMBER.lastIndex; continue; }
    IDENT.lastIndex = i;
    if (IDENT.exec(line)) {
      const word = line.slice(i, IDENT.lastIndex);
      let j = IDENT.lastIndex;
      if (line[j] === "!" && line[j + 1] !== "=") { push(out, word + "!", "mac"); i = j + 1; continue; }
      while (line[j] === " ") j++;
      const kind: TokenKind = RUST_KW.has(word) ? "kw" : /^[A-Z]/.test(word) ? "type" : line[j] === "(" ? "fn" : "plain";
      push(out, word, kind);
      i = IDENT.lastIndex;
      continue;
    }
    push(out, line[i], "plain");
    i++;
  }
  return mode;
}

function pythonLine(line: string, mode: Mode, out: Token[]): Mode {
  let i = 0;
  while (i < line.length) {
    if (mode.k === "str") {
      const end = closeString(line, i, mode.close);
      if (end < 0) { push(out, line.slice(i), "str"); return mode.close.length === 3 ? mode : { k: "code" }; }
      push(out, line.slice(i, end), "str");
      i = end;
      mode = { k: "code" };
      continue;
    }
    const rest = line.slice(i);
    if (rest.startsWith("#")) { push(out, rest, "com"); break; }
    const quote = /^[rbfuRBFU]{0,2}("""|'''|"|')/.exec(rest);
    if (quote) { push(out, quote[0], "str"); i += quote[0].length; mode = { k: "str", close: quote[1] }; continue; }
    const deco = /^@[A-Za-z_][\w.]*/.exec(rest);
    if (deco) { push(out, deco[0], "attr"); i += deco[0].length; continue; }
    NUMBER.lastIndex = i;
    if (/[0-9]/.test(line[i]) && NUMBER.exec(line)) { push(out, line.slice(i, NUMBER.lastIndex), "num"); i = NUMBER.lastIndex; continue; }
    IDENT.lastIndex = i;
    if (IDENT.exec(line)) {
      const word = line.slice(i, IDENT.lastIndex);
      const kind: TokenKind = PY_KW.has(word) ? "kw" : /^[A-Z]/.test(word) ? "type" : line[IDENT.lastIndex] === "(" ? "fn" : "plain";
      push(out, word, kind);
      i = IDENT.lastIndex;
      continue;
    }
    push(out, line[i], "plain");
    i++;
  }
  return mode;
}

function tomlLine(line: string, out: Token[]) {
  const header = /^\s*\[\[?[^\]]*\]\]?/.exec(line);
  if (header) { push(out, header[0], "type"); line = line.slice(header[0].length); }
  const key = /^\s*[A-Za-z0-9_.\-"]+\s*(?==)/.exec(line);
  if (key) { push(out, key[0], "attr"); line = line.slice(key[0].length); }
  const re = /("(?:\\.|[^"\\])*"?|'[^']*'?)|(#.*)|\b(true|false)\b|(\b\d[\d_.:\-TZ+]*\b)/g;
  let last = 0;
  for (let m = re.exec(line); m; m = re.exec(line)) {
    push(out, line.slice(last, m.index), "plain");
    push(out, m[0], m[1] ? "str" : m[2] ? "com" : m[3] ? "kw" : "num");
    last = m.index + m[0].length;
  }
  push(out, line.slice(last), "plain");
}

export function tokenize(lines: string[], language: string): Token[][] {
  let mode: Mode = { k: "code" };
  return lines.map((line) => {
    const out: Token[] = [];
    if (language === "rust") mode = rustLine(line, mode, out);
    else if (language === "python") mode = pythonLine(line, mode, out);
    else if (language === "toml") tomlLine(line, out);
    else push(out, line, "plain");
    return out;
  });
}
