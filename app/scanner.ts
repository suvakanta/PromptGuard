export type Finding = { title: string; snippet: string; severity: "Critical" | "High" | "Medium" | "Low"; confidence: number; category: string; remediation: string };

const rules = [
  { re: /ignore (all |any )?(previous|prior|above) instructions?/gi, title: "Instruction hierarchy override", severity: "Critical" as const, category: "Prompt override", confidence: 98, remediation: "Remove the instruction and keep system policy immutable." },
  { re: /(reveal|show|print|repeat).{0,35}(system prompt|hidden instructions?|developer message)/gi, title: "System prompt extraction", severity: "Critical" as const, category: "Data exfiltration", confidence: 97, remediation: "Block the request and prevent protected prompts from entering model output." },
  { re: /(send|forward|upload|transmit|post).{0,60}(external|@|https?:|webhook)/gi, title: "External data transfer", severity: "High" as const, category: "Exfiltration", confidence: 93, remediation: "Deny unapproved destinations and require explicit user authorization." },
  { re: /(do not mention|keep (this|it) secret|without telling|silently)/gi, title: "Output concealment", severity: "High" as const, category: "Evasion", confidence: 91, remediation: "Reject hidden side effects and surface the requested action to the user." },
  { re: /(base64|encode|decode|rot13|hex).{0,45}(data|content|message|salary|secret|credential)/gi, title: "Encoded payload request", severity: "High" as const, category: "Obfuscation", confidence: 89, remediation: "Decode in an isolated scanner and re-apply policy before use." },
  { re: /(act as|you are now|new role|switch roles?)/gi, title: "Role manipulation", severity: "Medium" as const, category: "Role hijacking", confidence: 78, remediation: "Treat role requests as untrusted content, not authority." },
  { re: /(bypass|disable|override).{0,40}(safety|security|filter|policy|guardrail)/gi, title: "Safety bypass attempt", severity: "Critical" as const, category: "Policy bypass", confidence: 96, remediation: "Block and preserve the event for security review." },
  { re: /(password|api[ _-]?key|access token|private key|credential).{0,45}(reveal|send|share|print|upload|expose)/gi, title: "Credential harvesting", severity: "Critical" as const, category: "Secrets", confidence: 95, remediation: "Block the request and rotate any credential that may have been exposed." },
  { re: /(click|open|visit|log ?in|verify).{0,35}(urgent|immediately|account|password|https?:\/\/)/gi, title: "Phishing-style call to action", severity: "High" as const, category: "Social engineering", confidence: 86, remediation: "Verify the sender and destination out of band before taking action." },
  { re: /(execute|run|invoke|call).{0,45}(shell|terminal|powershell|command|tool|function)/gi, title: "Unauthorized tool execution", severity: "High" as const, category: "Tool abuse", confidence: 90, remediation: "Require separate tool authorization and validate every argument." },
];

export function scanText(text: string): Finding[] {
  const normalized = text.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
  const found: Finding[] = [];
  for (const rule of rules) {
    rule.re.lastIndex = 0;
    const match = rule.re.exec(normalized);
    if (match) {
      const start = Math.max(0, match.index - 28);
      const end = Math.min(normalized.length, match.index + match[0].length + 48);
      found.push({ ...rule, snippet: `${start ? "…" : ""}${normalized.slice(start, end).replace(/\s+/g, " ")}${end < normalized.length ? "…" : ""}` });
    }
  }
  return found;
}

function decodeXml(value: string) {
  return value.replace(/&#(x?[\da-f]+);|&(?:amp|lt|gt|quot|apos);/gi, entity => {
    if (entity.startsWith("&#")) {
      const hex = entity[2].toLowerCase() === "x";
      return String.fromCodePoint(parseInt(entity.slice(hex ? 3 : 2, -1), hex ? 16 : 10));
    }
    return ({ "&amp;": "&", "&lt;": "<", "&gt;": ">", "&quot;": '"', "&apos;": "'" } as Record<string, string>)[entity.toLowerCase()] || entity;
  });
}

export function extractXmlText(xml: string) {
  return decodeXml(xml
    .replace(/<w:(?:tab|br|cr)\b[^>]*\/?\s*>/gi, " ")
    .replace(/<\/w:(?:p|tr|tc)>/gi, "\n")
    .replace(/<[^>]+>/g, " "))
    .replace(/[ \t]+/g, " ")
    .replace(/\n\s+/g, "\n")
    .trim();
}

function u16(view: DataView, offset: number) { return view.getUint16(offset, true); }
function u32(view: DataView, offset: number) { return view.getUint32(offset, true); }

async function inflate(data: Uint8Array, method: number) {
  if (method === 0) return data;
  if (method !== 8) throw new Error(`Unsupported DOCX compression method ${method}.`);
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(new DecompressionStream("deflate-raw"));
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Extracts all text-bearing OOXML parts, including headers, comments, notes,
 * custom XML, metadata and relationship targets—not only visible body text. */
export async function extractDocxText(file: File) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let eocd = bytes.length - 22;
  while (eocd >= Math.max(0, bytes.length - 65_557) && u32(view, eocd) !== 0x06054b50) eocd--;
  if (eocd < 0) throw new Error("This DOCX is not a valid ZIP package.");

  const entries = u16(view, eocd + 10);
  let cursor = u32(view, eocd + 16);
  const decoder = new TextDecoder();
  const parts: string[] = [];
  for (let i = 0; i < entries; i++) {
    if (u32(view, cursor) !== 0x02014b50) throw new Error("The DOCX directory is damaged.");
    const method = u16(view, cursor + 10);
    const compressedSize = u32(view, cursor + 20);
    const nameLength = u16(view, cursor + 28);
    const extraLength = u16(view, cursor + 30);
    const commentLength = u16(view, cursor + 32);
    const localOffset = u32(view, cursor + 42);
    const name = decoder.decode(bytes.subarray(cursor + 46, cursor + 46 + nameLength));
    const isTextPart = /^(word\/.*\.xml|customXml\/.*\.xml|docProps\/.*\.xml|word\/_rels\/.*\.rels)$/i.test(name);
    if (isTextPart && compressedSize <= 10_000_000) {
      const localNameLength = u16(view, localOffset + 26);
      const localExtraLength = u16(view, localOffset + 28);
      const dataStart = localOffset + 30 + localNameLength + localExtraLength;
      const xml = decoder.decode(await inflate(bytes.subarray(dataStart, dataStart + compressedSize), method));
      const text = extractXmlText(xml);
      const relationshipTargets = [...xml.matchAll(/\bTarget="([^"]+)"/gi)].map(match => decodeXml(match[1])).join(" ");
      if (text || relationshipTargets) parts.push(`[${name}]\n${text} ${relationshipTargets}`);
    }
    cursor += 46 + nameLength + extraLength + commentLength;
  }
  return parts.join("\n");
}
